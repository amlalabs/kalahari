// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Error types for the VMM API.
//!
//! Errors are organized into typed sub-enums (`ConfigError`, `DeviceError`)
//! so callers can match on specific conditions without parsing error message
//! strings.

use std::io;

/// Result type alias for VMM operations.
pub type Result<T> = std::result::Result<T, Error>;

/// VMM errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Hypervisor backend error.
    #[error("Backend error: {0}")]
    Backend(#[from] crate::backend::BackendError),

    /// vCPU error.
    #[error("vCPU error: {0}")]
    Vcpu(#[from] amla_core::VcpuError),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Invalid state transition.
    #[error("Invalid state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state description.
        expected: &'static str,
        /// Actual state description.
        actual: &'static str,
    },

    /// Device setup or operation error.
    #[error("Device error: {0}")]
    Device(#[from] DeviceError),

    /// All vCPUs exited before the user closure returned (fatal guest exit).
    #[error("all vCPUs exited before run closure completed (guest shutdown/reboot/error)")]
    VcpuExitedEarly,

    /// A VM transition failed, and the mandatory backend teardown also failed.
    #[error("{operation} failed with {source}; backend close also failed with {close}")]
    VmOperationFailedAndBackendCloseFailed {
        /// Operation being unwound.
        operation: &'static str,
        /// Original operation failure.
        source: Box<Self>,
        /// Failure from the awaited backend close.
        close: Box<Self>,
    },

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Memory management error.
    #[error("Memory error: {0}")]
    Memory(#[from] amla_mem::MemError),

    /// Core VMM error (memory layout, etc.).
    #[error("{0}")]
    Core(#[from] amla_core::VmmError),

    /// vCPU index out of range for the mmap slot array.
    #[error("vcpu index {index} out of range")]
    VcpuIndexOutOfRange {
        /// The invalid vCPU index.
        index: usize,
    },
}

impl Error {
    /// Return whether this error means the platform hypervisor exhausted host resources.
    ///
    /// This is used by higher-level schedulers to discover the live VM shell
    /// limit at runtime without parsing platform-specific error strings.
    #[must_use]
    // Reason: native clippy/rust 1.95 sees `is_resource_exhausted` as
    // const-eligible, but on the cross-build matrix the backend-specific
    // implementation calls non-const platform code. Keeping this non-const
    // remains portable across all supported targets.
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_backend_resource_exhausted(&self) -> bool {
        if let Self::Backend(error) = self {
            crate::backend::is_resource_exhausted(error)
        } else {
            false
        }
    }
}

// ─── Configuration errors ───────────────────────────────────────────────────

/// Configuration validation errors.
///
/// Returned when `VmConfig::validate()` detects an invalid configuration,
/// or when a required factory/backend is missing at setup time.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Subprocess worker binary not found.
    #[error(
        "subprocess worker binary not found: \
         build amla-kvm-worker (cargo build -p amla-vm-vmm --features subprocess \
         --bin amla-kvm-worker)"
    )]
    SubprocessWorkerNotFound,

    /// `memory_mb` is zero.
    #[error("memory_mb must be > 0")]
    ZeroMemory,

    /// `vcpu_count` is zero.
    #[error("vcpu_count must be > 0")]
    ZeroVcpus,

    /// `memory_mb` overflows when converted to bytes.
    #[error("memory_mb={memory_mb} overflows when converted to bytes")]
    MemoryOverflow {
        /// The configured memory size that overflowed.
        memory_mb: usize,
    },

    /// A pmem image size cannot be represented in the host layout.
    #[error(
        "pmem_disks[{disk_index}].images[{image_index}] image_size={image_size} is invalid: {reason}"
    )]
    PmemImageSizeInvalid {
        /// Index of the misconfigured pmem disk.
        disk_index: usize,
        /// Index of the misconfigured image in the disk.
        image_index: usize,
        /// Configured image size in bytes.
        image_size: u64,
        /// Validation failure details.
        reason: String,
    },

    /// A packed pmem disk size cannot be represented in the host layout.
    #[error("pmem_disks[{disk_index}] packed size={size} is invalid: {reason}")]
    PmemDiskSizeInvalid {
        /// Index of the misconfigured pmem disk.
        disk_index: usize,
        /// Packed, page-aligned data size in bytes.
        size: u64,
        /// Validation failure details.
        reason: String,
    },

    /// Config has net device but no net backend was provided.
    #[error("config has net but no net backend provided")]
    MissingNetBackend,

    /// Network backend enforces a guest MAC that does not match `VmConfig`.
    #[error("net backend guest MAC {backend:?} does not match VmConfig net MAC {config:?}")]
    NetBackendGuestMacMismatch {
        /// Guest MAC configured on the VM device.
        config: [u8; 6],
        /// Guest MAC enforced by the backend.
        backend: [u8; 6],
    },

    /// Config has fs device but no fs backend was provided.
    #[error("config has fs but no fs backend provided")]
    MissingFsBackend,

    /// Pmem image count doesn't match config's pmem disk count.
    #[error("pmem image count ({provided}) != config pmem_disks count ({expected})")]
    PmemCountMismatch {
        /// Number of images provided.
        provided: usize,
        /// Number of pmem disks in config.
        expected: usize,
    },

    /// GPA layout computation overflowed (too many vCPUs or devices).
    #[error("GPA layout overflow: vcpu_count={vcpu_count}, device_count={device_count}")]
    GpaLayoutOverflow {
        /// Configured vCPU count.
        vcpu_count: usize,
        /// Number of devices in the layout.
        device_count: usize,
    },

    /// Kernel boot setup failed.
    #[error("boot setup: {0}")]
    BootSetup(#[from] amla_boot::BootError),

    /// Device layout exceeds MMIO slot or IRQ capacity.
    #[error("device layout has {count} devices, max {max}")]
    TooManyDevices {
        /// Number of devices in the layout.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Device queue wake layout exceeds the waker bitset capacity.
    #[error("device queue wake layout has {count} wake bits, max {max}")]
    TooManyQueueWakes {
        /// Number of queue wake bits in the layout.
        count: usize,
        /// Maximum supported by the waker bitset.
        max: usize,
    },

    /// IRQ allocation failed while building a device layout.
    #[error("IRQ allocation failed: {reason}")]
    IrqAllocation {
        /// Allocation failure details.
        reason: String,
    },

    /// Multiple devices have `mount_path == "/"`.
    #[error("multiple root devices: {count} devices have mount_path=\"/\"")]
    MultipleRootDevices {
        /// Number of root devices found.
        count: usize,
    },

    /// A pmem disk has no images.
    #[error("pmem_disks[{index}] has no images")]
    EmptyPmemDisk {
        /// Index of the empty disk in `pmem_disks`.
        index: usize,
    },

    /// A non-overlay pmem image is missing its guest mount path.
    #[error(
        "pmem_disks[{disk_index}].images[{image_index}] requires mount_path without overlay_target"
    )]
    PmemImageMissingMountPath {
        /// Index of the misconfigured pmem disk.
        disk_index: usize,
        /// Index of the misconfigured image in the disk.
        image_index: usize,
    },

    /// An overlay pmem image has a mount path that would be ignored.
    #[error(
        "pmem_disks[{disk_index}].images[{image_index}] must not set mount_path with overlay_target"
    )]
    PmemImageMountPathWithOverlay {
        /// Index of the misconfigured pmem disk.
        disk_index: usize,
        /// Index of the misconfigured image in the disk.
        image_index: usize,
    },

    /// A pmem overlay targets the guest root filesystem.
    #[error("pmem_disks[{disk_index}].overlay_target must not be /")]
    OverlayTargetRoot {
        /// Index of the misconfigured pmem disk.
        disk_index: usize,
    },

    /// `overlay_upper_tag` set without `overlay_target`.
    #[error("pmem_disks[{index}]: overlay_upper_tag requires overlay_target")]
    UpperTagWithoutOverlay {
        /// Index of the misconfigured disk.
        index: usize,
    },

    /// `overlay_upper_tag` doesn't match any configured `FsConfig` tag.
    #[error("pmem_disks[{index}]: overlay_upper_tag {tag:?} does not match any fs tag")]
    UnknownOverlayUpperTag {
        /// Index of the misconfigured disk.
        index: usize,
        /// The unmatched tag.
        tag: String,
    },

    /// Two effective mount operations target the same guest path.
    #[error("duplicate guest mount path {path:?}: first {first}, second {second}")]
    DuplicateMountPath {
        /// The duplicated guest path.
        path: String,
        /// First owner in the VM config.
        first: String,
        /// Second owner in the VM config.
        second: String,
    },

    /// Two overlay disks use the same writable upper virtiofs tag.
    #[error("duplicate overlay upper tag {tag:?}: pmem_disks[{first}] and pmem_disks[{second}]")]
    DuplicateOverlayUpperTag {
        /// The duplicated virtiofs tag.
        tag: String,
        /// First pmem disk using this upper.
        first: usize,
        /// Second pmem disk using this upper.
        second: usize,
    },

    /// Pool `vcpu_count` doesn't match config `vcpu_count`.
    #[error("pool vcpu_count ({pool}) != config vcpu_count ({config})")]
    VcpuCountMismatch {
        /// Pool's `vcpu_count`.
        pool: usize,
        /// Config's `vcpu_count`.
        config: usize,
    },

    /// Pool device topology doesn't match config device topology.
    #[error("pool device layout {pool:?} != config device layout {config:?}")]
    DeviceLayoutMismatch {
        /// Pool's `(kind, queue_count)` device topology.
        pool: Vec<(crate::devices::DeviceKind, usize)>,
        /// Config's `(kind, queue_count)` device topology.
        config: Vec<(crate::devices::DeviceKind, usize)>,
    },

    /// `vcpu_count` exceeds `MAX_VCPUS`.
    #[error("vcpu_count ({count}) exceeds MAX_VCPUS ({limit})")]
    VcpuExceedsLimit {
        /// The configured count.
        count: usize,
        /// The hard limit.
        limit: usize,
    },

    /// `memory_mb` below minimum.
    #[error("memory_mb ({memory_mb}) < MIN_MEMORY_MB ({min})")]
    MemoryTooSmall {
        /// The configured memory size.
        memory_mb: usize,
        /// The minimum.
        min: usize,
    },

    /// `memory_mb` is not aligned to block size.
    #[error("{field} ({value}) is not aligned to {align} MiB")]
    MemoryNotAligned {
        /// Which field is misaligned.
        field: &'static str,
        /// The misaligned value.
        value: usize,
        /// Required alignment in MiB.
        align: usize,
    },

    /// `cmdline_extra` contains a reserved key or disallowed byte.
    #[error("cmdline_extra invalid: {reason}")]
    CmdlineExtraInvalid {
        /// What made the string invalid.
        reason: String,
    },

    /// A virtio-fs tag failed validation.
    #[error("virtiofs tag {value:?} invalid: {reason}")]
    InvalidVirtioFsTag {
        /// The rejected tag.
        value: String,
        /// What made the tag invalid.
        reason: String,
    },

    /// A guest path failed validation.
    #[error("guest path {value:?} invalid: {reason}")]
    InvalidGuestPath {
        /// The rejected path.
        value: String,
        /// What made the path invalid.
        reason: String,
    },

    /// `NetConfig.queue_pairs` is outside the supported range.
    #[error("net.queue_pairs ({value}) out of range 1..={max}")]
    NetQueuePairsOutOfRange {
        /// The rejected value.
        value: u16,
        /// Inclusive upper bound.
        max: u16,
    },

    /// `FsConfig.num_request_queues` is outside the supported range.
    #[error("fs.num_request_queues ({value}) out of range 1..={max}")]
    FsRequestQueuesOutOfRange {
        /// The rejected value.
        value: u32,
        /// Inclusive upper bound.
        max: u32,
    },
}

// ─── Device errors ──────────────────────────────────────────────────────────

/// Device setup and operation errors.
///
/// Covers device creation, restore, IRQ wiring, and platform support checks.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// Feature requires a different platform (e.g., Unix/KVM).
    #[error("{feature} not supported on this platform")]
    PlatformUnsupported {
        /// The feature that requires a different platform.
        feature: &'static str,
    },

    /// Failed to create an IRQ line for a device.
    #[error("failed to create {kind} IRQ line: {source}")]
    IrqCreation {
        /// Device kind (e.g., "Console", "Net").
        kind: String,
        /// Underlying IRQ creation error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Pmem device setup failed (mapping or backend registration).
    #[error("pmem[{index}] setup: {source}")]
    PmemSetup {
        /// Pmem device index.
        index: usize,
        /// Underlying memory error.
        #[source]
        source: amla_mem::MemError,
    },

    /// A device did not quiesce before the stop/snapshot deadline.
    #[error("{device} did not quiesce within {timeout_ms}ms")]
    QuiesceTimeout {
        /// Device name.
        device: &'static str,
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },

    /// A synchronous device still had work after the bounded shutdown drain.
    #[error(
        "{device} queue {queue_idx} still had work after {max_rounds} shutdown drain rounds (wake bit {wake_idx})"
    )]
    ShutdownDrainExhausted {
        /// Device kind.
        device: crate::DeviceKind,
        /// Global wake bit index.
        wake_idx: usize,
        /// Virtqueue index inside the device.
        queue_idx: usize,
        /// Maximum drain rounds attempted.
        max_rounds: u32,
    },

    /// A component still had transient host-side state when `run()` stopped.
    #[error("{component} is not snapshot-quiescent: {detail}")]
    SnapshotNotQuiescent {
        /// Component name.
        component: &'static str,
        /// Human-readable quiescence failure.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_zero_memory() {
        let e: Error = ConfigError::ZeroMemory.into();
        let msg = e.to_string();
        assert!(msg.contains("Configuration"), "{msg}");
        assert!(msg.contains("memory_mb must be > 0"), "{msg}");
    }

    #[test]
    fn config_zero_vcpus() {
        let e: Error = ConfigError::ZeroVcpus.into();
        assert!(e.to_string().contains("vcpu_count"), "{e}");
    }

    #[test]
    fn device_platform_unsupported() {
        let e: Error = DeviceError::PlatformUnsupported {
            feature: "virtio-pmem",
        }
        .into();
        assert!(e.to_string().contains("virtio-pmem"), "{e}");
    }

    #[test]
    fn vcpu_index_out_of_range() {
        let e = Error::VcpuIndexOutOfRange { index: 99 };
        let msg = e.to_string();
        assert!(msg.contains("vcpu index 99 out of range"), "{msg}");
    }

    #[test]
    fn io_error_from() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let e: Error = io_err.into();
        assert!(e.to_string().contains("file not found"), "{e}");
    }

    #[test]
    fn invalid_state() {
        let e = Error::InvalidState {
            expected: "Running",
            actual: "Ready",
        };
        let msg = e.to_string();
        assert!(msg.contains("Running"), "{msg}");
        assert!(msg.contains("Ready"), "{msg}");
    }

    #[test]
    fn config_memory_overflow() {
        let e = ConfigError::MemoryOverflow { memory_mb: 99999 };
        let msg = e.to_string();
        assert!(msg.contains("99999"), "{msg}");
        assert!(msg.contains("overflow"), "{msg}");
    }

    #[test]
    fn config_missing_net_backend() {
        let e = ConfigError::MissingNetBackend;
        assert!(e.to_string().contains("net"), "{e}");
    }

    #[test]
    fn config_net_backend_guest_mac_mismatch() {
        let e = ConfigError::NetBackendGuestMacMismatch {
            config: [1, 2, 3, 4, 5, 6],
            backend: [6, 5, 4, 3, 2, 1],
        };
        let msg = e.to_string();
        assert!(msg.contains("guest MAC"), "{msg}");
        assert!(msg.contains("VmConfig"), "{msg}");
    }

    #[test]
    fn config_missing_fs_backend() {
        let e = ConfigError::MissingFsBackend;
        assert!(e.to_string().contains("fs"), "{e}");
    }

    #[test]
    fn config_pmem_count_mismatch() {
        let e = ConfigError::PmemCountMismatch {
            provided: 1,
            expected: 3,
        };
        let msg = e.to_string();
        assert!(msg.contains('1'), "{msg}");
        assert!(msg.contains('3'), "{msg}");
    }

    #[test]
    fn config_gpa_layout_overflow() {
        let e = ConfigError::GpaLayoutOverflow {
            vcpu_count: 256,
            device_count: 64,
        };
        let msg = e.to_string();
        assert!(msg.contains("256"), "{msg}");
        assert!(msg.contains("64"), "{msg}");
    }

    #[test]
    fn config_too_many_devices() {
        let e = ConfigError::TooManyDevices { count: 50, max: 32 };
        let msg = e.to_string();
        assert!(msg.contains("50"), "{msg}");
        assert!(msg.contains("32"), "{msg}");
    }

    #[test]
    fn config_multiple_root_devices() {
        let e = ConfigError::MultipleRootDevices { count: 3 };
        let msg = e.to_string();
        assert!(msg.contains('3'), "{msg}");
        assert!(msg.contains("root"), "{msg}");
    }

    #[test]
    fn config_vcpu_count_mismatch() {
        let e = ConfigError::VcpuCountMismatch { pool: 4, config: 2 };
        let msg = e.to_string();
        assert!(msg.contains('4'), "{msg}");
        assert!(msg.contains('2'), "{msg}");
    }

    #[test]
    fn config_vcpu_exceeds_limit() {
        let e = ConfigError::VcpuExceedsLimit {
            count: 256,
            limit: 128,
        };
        let msg = e.to_string();
        assert!(msg.contains("256"), "{msg}");
        assert!(msg.contains("128"), "{msg}");
    }

    #[test]
    fn config_empty_pmem_disk() {
        let e = ConfigError::EmptyPmemDisk { index: 2 };
        let msg = e.to_string();
        assert!(msg.contains('2'), "{msg}");
        assert!(msg.contains("no images"), "{msg}");
    }

    #[test]
    fn device_irq_creation() {
        let e = DeviceError::IrqCreation {
            kind: "Console".into(),
            source: "irq alloc failed".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("Console"), "{msg}");
        assert!(msg.contains("IRQ"), "{msg}");
    }
}
