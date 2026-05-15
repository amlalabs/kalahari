// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! VM configuration types.
//!
//! `VmConfig` configures memory, vCPUs, and standard devices. Defaults provide
//! a sensible starting point for most use cases.
//!
//! Pmem images are passed as `MemHandle`s — callers create them via
//! `MemHandle::allocate_and_write()` or `MemHandle::from_file()`.

use std::collections::BTreeMap;
use std::fmt;

use amla_constants::net::DEFAULT_GUEST_MAC;
use serde::{Deserialize, Serialize};

use crate::devices::DeviceKind;

const GUEST_PATH_MAX_BYTES: usize = 83;

/// A validated virtio-fs tag.
///
/// Tags are copied into the virtio-fs device config space and may also appear
/// as kernel `root=` values. They must therefore fit the device config field
/// and avoid bytes that would be parsed as cmdline separators.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct VirtioFsTag(String);

impl VirtioFsTag {
    /// Parse and validate a virtio-fs tag.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidVirtioFsTag`] if the tag is empty,
    /// overlong, NUL-containing, or contains ASCII whitespace.
    pub fn new(tag: impl AsRef<str>) -> Result<Self, crate::ConfigError> {
        Self::try_from(tag.as_ref().to_owned())
    }

    /// Return the tag as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the tag length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the tag is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<str> for VirtioFsTag {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for VirtioFsTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for VirtioFsTag {
    type Error = crate::ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_virtiofs_tag(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for VirtioFsTag {
    type Error = crate::ConfigError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for VirtioFsTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// A validated absolute guest filesystem path.
///
/// Guest paths are sent over the setup protocol and may be embedded in overlay
/// mount option strings inside the guest agent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestPath(String);

impl GuestPath {
    /// Parse and validate an absolute guest path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidGuestPath`] if the path is empty,
    /// relative, non-canonical, too long for durable device metadata, contains
    /// control characters, or contains overlay option delimiters.
    pub fn new(path: impl AsRef<str>) -> Result<Self, crate::ConfigError> {
        Self::try_from(path.as_ref().to_owned())
    }

    /// Return the guest root path.
    #[must_use]
    pub fn root() -> Self {
        Self(String::from("/"))
    }

    /// Return the path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return whether this path is the guest root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }
}

impl AsRef<str> for GuestPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for GuestPath {
    type Error = crate::ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_guest_path(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for GuestPath {
    type Error = crate::ConfigError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for GuestPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// A validated single kernel command-line atom.
///
/// One atom is one whitespace-free `/proc/cmdline` token such as `quiet` or
/// `key=value`. Caller-supplied atoms reject keys reserved by the VMM.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct KernelCmdlineAtom(String);

impl KernelCmdlineAtom {
    /// Parse and validate a caller-supplied kernel cmdline atom.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::CmdlineExtraInvalid`] if the atom is empty,
    /// contains bytes the kernel treats as separators, or uses a reserved key.
    pub fn new(atom: impl AsRef<str>) -> Result<Self, crate::ConfigError> {
        let atom = atom.as_ref().to_owned();
        validate_cmdline_atom(&atom)?;
        reject_reserved_cmdline_key(&atom)?;
        Ok(Self(atom))
    }

    pub(crate) fn generated(atom: impl Into<String>) -> Result<Self, crate::ConfigError> {
        let atom = atom.into();
        validate_cmdline_atom(&atom)?;
        Ok(Self(atom))
    }

    /// Return the atom as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for KernelCmdlineAtom {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for KernelCmdlineAtom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for KernelCmdlineAtom {
    type Error = crate::ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for KernelCmdlineAtom {
    type Error = crate::ConfigError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for KernelCmdlineAtom {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// Canonical backend-relevant VM device topology.
///
/// This is the public, hashable token used by higher-level schedulers to cache
/// backend pools without depending on `amla-vm-vmm`'s private typed device
/// layout. Entries are in MMIO device-slot order and include the exact virtqueue
/// count for every device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmTopology {
    entries: Vec<VmTopologyEntry>,
}

impl VmTopology {
    pub(crate) fn from_entries(entries: Vec<(DeviceKind, usize)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(kind, queue_count)| VmTopologyEntry { kind, queue_count })
                .collect(),
        }
    }

    /// Topology entries in MMIO device-slot order.
    #[must_use]
    pub fn entries(&self) -> &[VmTopologyEntry] {
        &self.entries
    }
}

/// One canonical device topology entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmTopologyEntry {
    /// Device kind in this slot.
    pub kind: DeviceKind,
    /// Exact virtqueue count for this device.
    pub queue_count: usize,
}

impl VmTopologyEntry {
    /// Create a topology entry.
    #[must_use]
    pub const fn new(kind: DeviceKind, queue_count: usize) -> Self {
        Self { kind, queue_count }
    }
}

/// An EROFS image exposed as a virtio-pmem device.
///
/// The guest agent mounts `/dev/pmemN` at the specified path with
/// `dax=always` for zero-copy access through the guest page tables.
///
/// When `mount_path` is `"/"`, the kernel mounts this device as the root
/// filesystem via cmdline params (`root=/dev/pmemN rootfstype=erofs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmemDiskConfig {
    /// Images packed into this device. Each gets its own `MemHandle`.
    pub images: Vec<PmemImageConfig>,
    /// When set, `build_mount_ops` wraps all images in an overlayfs
    /// mounted at this path.
    /// When `None`, images are mounted individually at their `mount_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_target: Option<GuestPath>,
    /// Virtiofs tag to use as the overlay upper directory.
    ///
    /// When `Some(tag)`, the overlay uses `VirtioFs { tag }` as upper
    /// (writes go through virtiofs to the host backend).
    /// When `None`, the guest creates a tmpfs upper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_upper_tag: Option<VirtioFsTag>,
}

/// A single EROFS image within a pmem device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmemImageConfig {
    /// Image size in bytes.
    pub image_size: u64,
    /// Guest mount path. `"/"` means root filesystem (kernel-mounted).
    ///
    /// Overlay-only images can leave this unset because the guest agent mounts
    /// them at generated temporary paths before composing the overlay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<GuestPath>,
}

impl PmemImageConfig {
    /// Create a pmem image with an explicit guest mount path.
    #[must_use]
    pub const fn new(image_size: u64, mount_path: GuestPath) -> Self {
        Self {
            image_size,
            mount_path: Some(mount_path),
        }
    }

    /// Parse a guest path and create a pmem image with that mount path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidGuestPath`] if `mount_path` is not
    /// a valid guest path.
    pub fn try_new(
        image_size: u64,
        mount_path: impl AsRef<str>,
    ) -> Result<Self, crate::ConfigError> {
        Ok(Self::new(image_size, GuestPath::new(mount_path)?))
    }

    /// Create a pmem image intended only for overlay composition.
    #[must_use]
    pub const fn overlay(image_size: u64) -> Self {
        Self {
            image_size,
            mount_path: None,
        }
    }
}

/// Network device configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConfig {
    /// Guest NIC MAC address. If `None`, uses
    /// [`DEFAULT_GUEST_MAC`](amla_constants::net::DEFAULT_GUEST_MAC).
    pub mac_address: Option<[u8; 6]>,
    /// Number of queue pairs (1..=5). More pairs allow parallel network I/O.
    #[serde(default = "default_net_queue_pairs")]
    pub queue_pairs: u16,
}

const fn default_net_queue_pairs() -> u16 {
    5
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            mac_address: None,
            queue_pairs: default_net_queue_pairs(),
        }
    }
}

impl NetConfig {
    /// Set the MAC address.
    #[must_use]
    pub const fn mac(mut self, mac: [u8; 6]) -> Self {
        self.mac_address = Some(mac);
        self
    }

    /// Return the concrete guest NIC MAC for this config.
    #[must_use]
    pub fn guest_mac(&self) -> [u8; 6] {
        self.mac_address.unwrap_or(DEFAULT_GUEST_MAC)
    }

    /// Set the number of queue pairs.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::NetQueuePairsOutOfRange`] if `n` is not in
    /// `1..=amla_virtio_net::MAX_QUEUE_PAIRS`.
    pub fn queue_pairs(mut self, n: u16) -> Result<Self, crate::ConfigError> {
        if !(1..=amla_virtio_net::MAX_QUEUE_PAIRS).contains(&n) {
            return Err(crate::ConfigError::NetQueuePairsOutOfRange {
                value: n,
                max: amla_virtio_net::MAX_QUEUE_PAIRS,
            });
        }
        self.queue_pairs = n;
        Ok(self)
    }
}

/// Filesystem device configuration.
///
/// The backend is provided separately via `FsBackendFactory`; this struct
/// only configures the virtio transport (tag, mount path).
///
/// EROFS images are served via virtio-pmem, not virtiofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsConfig {
    /// Tag for the virtiofs mount (used in guest: `mount -t virtiofs TAG /mnt`).
    pub tag: VirtioFsTag,
    /// Guest mount path for direct mounting.
    ///
    /// When the tag is also used as an `overlay_upper_tag` in a pmem disk,
    /// the device is consumed by the overlay and this path is ignored.
    pub mount_path: GuestPath,
    /// Number of request queues (1..=9). More queues allow parallel FUSE ops.
    ///
    /// Defaults to 9. Typical value: match guest vCPU count, capped by the
    /// virtio-fs state layout.
    #[serde(default = "default_num_request_queues")]
    pub num_request_queues: FsRequestQueueCount,
}

const fn default_num_request_queues() -> FsRequestQueueCount {
    FsRequestQueueCount::DEFAULT
}

/// Validated virtio-fs request queue count stored in [`FsConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FsRequestQueueCount(amla_virtio_fs::RequestQueueCount);

impl FsRequestQueueCount {
    /// Default request queue count used by [`FsConfig`].
    pub const DEFAULT: Self = Self(amla_virtio_fs::RequestQueueCount::MAX);

    /// Validate a raw request queue count.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::FsRequestQueuesOutOfRange`] when `value`
    /// is outside `1..=amla_virtio_fs::MAX_REQUEST_QUEUES`.
    pub fn new(value: u32) -> Result<Self, crate::ConfigError> {
        let count = amla_virtio_fs::RequestQueueCount::try_from(value).map_err(|err| {
            crate::ConfigError::FsRequestQueuesOutOfRange {
                value: err.value(),
                max: amla_virtio_fs::MAX_REQUEST_QUEUES,
            }
        })?;
        Ok(Self(count))
    }

    /// Return the transport-level queue-count token.
    #[must_use]
    pub const fn virtio(self) -> amla_virtio_fs::RequestQueueCount {
        self.0
    }

    /// Return the validated count as `u32`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0.as_u32()
    }
}

impl TryFrom<u32> for FsRequestQueueCount {
    type Error = crate::ConfigError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FsRequestQueueCount> for u32 {
    fn from(value: FsRequestQueueCount) -> Self {
        value.as_u32()
    }
}

impl Default for FsRequestQueueCount {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Serialize for FsRequestQueueCount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.as_u32())
    }
}

impl<'de> Deserialize<'de> for FsRequestQueueCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Bytes reserved for the virtio-fs tag in device config space.
pub const VIRTIO_FS_TAG_CONFIG_LEN: usize = 36;
const VIRTIO_FS_TAG_MAX_BYTES: usize = VIRTIO_FS_TAG_CONFIG_LEN - 1;

impl FsConfig {
    /// Create a virtiofs config with the given tag and mount path.
    ///
    /// Use `mount_path = "/"` for a root filesystem (kernel boots from it).
    #[must_use]
    pub const fn new(tag: VirtioFsTag, mount_path: GuestPath) -> Self {
        Self {
            tag,
            mount_path,
            num_request_queues: default_num_request_queues(),
        }
    }

    /// Parse a virtiofs tag and guest mount path, then create a config.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidVirtioFsTag`] or
    /// [`crate::ConfigError::InvalidGuestPath`] if either string is invalid.
    pub fn try_new(
        tag: impl AsRef<str>,
        mount_path: impl AsRef<str>,
    ) -> Result<Self, crate::ConfigError> {
        Ok(Self::new(
            VirtioFsTag::new(tag)?,
            GuestPath::new(mount_path)?,
        ))
    }

    /// Create a root virtiofs config (kernel boots from this filesystem).
    #[must_use]
    pub fn root(tag: VirtioFsTag) -> Self {
        Self::new(tag, GuestPath::root())
    }

    /// Parse a virtiofs tag, then create a root virtiofs config.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidVirtioFsTag`] if `tag` is invalid.
    pub fn try_root(tag: impl AsRef<str>) -> Result<Self, crate::ConfigError> {
        Ok(Self::root(VirtioFsTag::new(tag)?))
    }

    /// Set the number of request queues.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::FsRequestQueuesOutOfRange`] if `n` is not in
    /// `1..=amla_virtio_fs::MAX_REQUEST_QUEUES`.
    pub fn with_request_queues(mut self, n: u32) -> Result<Self, crate::ConfigError> {
        self.num_request_queues = FsRequestQueueCount::new(n)?;
        Ok(self)
    }
}

/// VM configuration.
///
/// # Defaults
///
/// - Memory: 256 MB
/// - vCPUs: 1
/// - RNG, console: always enabled (unconditional)
/// - Network: disabled (requires caller-provided net backend)
/// - Filesystem: disabled (requires path)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Memory size in megabytes (initial RAM).
    pub memory_mb: usize,
    /// Number of vCPUs.
    pub vcpu_count: u32,
    /// Network device configuration.
    pub net: Option<NetConfig>,
    /// Filesystem device configuration (virtiofs).
    pub fs: Option<FsConfig>,
    /// EROFS images exposed as virtio-pmem devices.
    ///
    /// Each gets its own device; the guest agent mounts `/dev/pmemN` at
    /// the specified path with `dax=always`. Image fds are transferred
    /// separately via `SCM_RIGHTS`.
    #[serde(default)]
    pub pmem_disks: Vec<PmemDiskConfig>,
    /// Extra kernel cmdline parameters appended after base + device params.
    ///
    /// Use this for caller-specific params (e.g. bench knobs). The base
    /// cmdline (`console=... init=/bin/guest_agent`) and device fragments
    /// (virtio-mmio, root=, rootfstype=) are built automatically by
    /// `load_kernel()`. Any key this crate sets automatically (see
    /// `RESERVED_CMDLINE_KEYS`) is rejected by [`VmConfig::validate()`] —
    /// letting a caller override `init=` or `root=` would bypass the sandboxed
    /// guest agent and root filesystem selection.
    #[serde(default)]
    pub cmdline_extra: Vec<KernelCmdlineAtom>,
}

/// Kernel cmdline keys set automatically by this crate. Callers may not
/// override them via `cmdline_extra`: they select the init binary, the root
/// filesystem, and the console the VMM reads from — letting userland retarget
/// them would defeat the sandbox. Kept as a prefix list so that e.g. any
/// `rootflags=...` (not just a bare `root=`) is blocked.
const RESERVED_CMDLINE_KEYS: &[&str] = &[
    "init",
    "rdinit",
    "root",
    "rootfstype",
    "rootflags",
    "console",
    "earlycon",
    "amla_ring",
    "virtio_mmio.device",
];

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            memory_mb: 256, // must be >= MIN_MEMORY_MB and aligned to BLOCK_SIZE_MB
            vcpu_count: 1,
            net: None,
            fs: None,
            pmem_disks: Vec::new(),
            cmdline_extra: Vec::new(),
        }
    }
}

impl VmConfig {
    /// Set memory size in megabytes.
    #[must_use]
    pub const fn memory_mb(mut self, mb: usize) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set number of vCPUs.
    #[must_use]
    pub const fn vcpu_count(mut self, count: u32) -> Self {
        self.vcpu_count = count;
        self
    }

    /// Configure network device.
    #[must_use]
    pub const fn net(mut self, config: NetConfig) -> Self {
        self.net = Some(config);
        self
    }

    /// Configure the virtiofs device.
    #[must_use]
    pub fn fs(mut self, config: FsConfig) -> Self {
        self.fs = Some(config);
        self
    }

    /// Add a virtio-pmem device with a single EROFS image.
    #[must_use]
    pub fn pmem_disk(mut self, image_size: u64, mount_path: GuestPath) -> Self {
        self.pmem_disks.push(PmemDiskConfig {
            images: vec![PmemImageConfig::new(image_size, mount_path)],
            overlay_target: None,
            overlay_upper_tag: None,
        });
        self
    }

    /// Parse a guest path and add a virtio-pmem device with a single EROFS image.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidGuestPath`] if `mount_path` is not
    /// a valid guest path.
    pub fn try_pmem_disk(
        self,
        image_size: u64,
        mount_path: impl AsRef<str>,
    ) -> Result<Self, crate::ConfigError> {
        Ok(self.pmem_disk(image_size, GuestPath::new(mount_path)?))
    }

    /// Add a virtio-pmem device as the kernel root filesystem.
    #[must_use]
    pub fn pmem_root(self, image_size: u64) -> Self {
        let mut config = self;
        config.pmem_disks.push(PmemDiskConfig {
            images: vec![PmemImageConfig {
                image_size,
                mount_path: Some(GuestPath::root()),
            }],
            overlay_target: None,
            overlay_upper_tag: None,
        });
        config
    }

    /// Add a virtio-pmem device with multiple packed EROFS images.
    #[must_use]
    pub fn pmem_packed(mut self, images: Vec<PmemImageConfig>) -> Self {
        self.pmem_disks.push(PmemDiskConfig {
            images,
            overlay_target: None,
            overlay_upper_tag: None,
        });
        self
    }

    /// Add a virtio-pmem device with images overlaid to `target`.
    ///
    /// The guest agent mounts each image at a temp dir, then creates
    /// `overlayfs(lower=[images], upper=tmpfs)` at `target`.
    #[must_use]
    pub fn pmem_overlay(mut self, images: Vec<PmemImageConfig>, target: GuestPath) -> Self {
        self.pmem_disks.push(PmemDiskConfig {
            images,
            overlay_target: Some(target),
            overlay_upper_tag: None,
        });
        self
    }

    /// Parse a guest target path and add an overlaid virtio-pmem device.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidGuestPath`] if `target` is not a
    /// valid guest path.
    pub fn try_pmem_overlay(
        self,
        images: Vec<PmemImageConfig>,
        target: impl AsRef<str>,
    ) -> Result<Self, crate::ConfigError> {
        Ok(self.pmem_overlay(images, GuestPath::new(target)?))
    }

    /// Add a virtio-pmem device with images overlaid to `target`, using
    /// a virtiofs device as the writable upper directory.
    ///
    /// `upper_tag` must match a virtiofs device configured via [`VmConfig::fs()`].
    /// The guest agent mounts each image at a temp dir, then creates
    /// `overlayfs(lower=[images], upper=virtiofs(upper_tag))` at `target`.
    #[must_use]
    pub fn pmem_overlay_with_upper(
        mut self,
        images: Vec<PmemImageConfig>,
        target: GuestPath,
        upper_tag: VirtioFsTag,
    ) -> Self {
        self.pmem_disks.push(PmemDiskConfig {
            images,
            overlay_target: Some(target),
            overlay_upper_tag: Some(upper_tag),
        });
        self
    }

    /// Parse a guest target path and virtiofs upper tag, then add an overlay.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::InvalidGuestPath`] if `target` is invalid,
    /// or [`crate::ConfigError::InvalidVirtioFsTag`] if `upper_tag` is invalid.
    pub fn try_pmem_overlay_with_upper(
        self,
        images: Vec<PmemImageConfig>,
        target: impl AsRef<str>,
        upper_tag: impl AsRef<str>,
    ) -> Result<Self, crate::ConfigError> {
        Ok(self.pmem_overlay_with_upper(
            images,
            GuestPath::new(target)?,
            VirtioFsTag::new(upper_tag)?,
        ))
    }

    /// Set extra kernel cmdline atoms appended after base and device params.
    #[must_use]
    pub fn cmdline_extra(mut self, extra: impl IntoIterator<Item = KernelCmdlineAtom>) -> Self {
        self.cmdline_extra = extra.into_iter().collect();
        self
    }

    /// Parse extra kernel cmdline parameters from a whitespace-separated string.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigError::CmdlineExtraInvalid`] if any parsed atom is
    /// invalid or tries to set a reserved VMM-owned key.
    pub fn try_cmdline_extra(mut self, extra: impl AsRef<str>) -> Result<Self, crate::ConfigError> {
        self.cmdline_extra = parse_cmdline_extra(extra.as_ref())?;
        Ok(self)
    }

    /// Validate the configuration, returning an error for invalid values.
    ///
    /// Checks:
    /// - `memory_mb` and `vcpu_count` are non-zero (zero causes backend hang)
    /// - `memory_mb` doesn't overflow when converted to bytes
    /// - Device layout fits within interrupt controller limits
    pub fn validate(&self) -> crate::Result<()> {
        self.validate_memory()?;
        self.validate_vcpus()?;
        self.validate_pmem_disks()?;
        self.validate_root_count()?;
        self.validate_effective_mount_paths()?;
        self.validate_device_layout()?;
        self.validate_net()?;
        validate_cmdline_extra(&self.cmdline_extra)?;
        Ok(())
    }

    /// Return the canonical backend-relevant topology for this VM config.
    ///
    /// The returned token is suitable for exact backend-pool matching and
    /// scheduler cache keys. It includes only topology fields that affect shell
    /// construction: device kind order and per-device virtqueue counts.
    pub fn topology(&self) -> crate::Result<VmTopology> {
        let layout = crate::devices::DeviceLayout::from_config(self)?;
        Ok(VmTopology::from_entries(layout.diagnostic_entries()))
    }

    /// Packed, host-page-aligned PMEM data sizes, one per PMEM disk.
    pub(crate) fn pmem_data_sizes(&self) -> crate::Result<Vec<u64>> {
        self.pmem_disks
            .iter()
            .enumerate()
            .map(|(disk_index, disk)| checked_pmem_disk_data_size(disk_index, disk))
            .collect()
    }

    fn validate_memory(&self) -> crate::Result<()> {
        use crate::ConfigError;
        if self.memory_mb == 0 {
            return Err(ConfigError::ZeroMemory.into());
        }
        if self.memory_mb < amla_core::MIN_MEMORY_MB {
            return Err(ConfigError::MemoryTooSmall {
                memory_mb: self.memory_mb,
                min: amla_core::MIN_MEMORY_MB,
            }
            .into());
        }
        if !self.memory_mb.is_multiple_of(amla_core::BLOCK_SIZE_MB) {
            return Err(ConfigError::MemoryNotAligned {
                field: "memory_mb",
                value: self.memory_mb,
                align: amla_core::BLOCK_SIZE_MB,
            }
            .into());
        }
        // Catch overflow early with a clear error rather than hitting a
        // confusing memory-size mismatch during snapshot restore.
        if self.memory_mb.checked_mul(1024 * 1024).is_none() {
            return Err(ConfigError::MemoryOverflow {
                memory_mb: self.memory_mb,
            }
            .into());
        }
        Ok(())
    }

    fn validate_vcpus(&self) -> crate::Result<()> {
        use crate::ConfigError;
        if self.vcpu_count == 0 {
            return Err(ConfigError::ZeroVcpus.into());
        }
        if self.vcpu_count as usize > amla_core::vm_state::MAX_VCPUS {
            return Err(ConfigError::VcpuExceedsLimit {
                count: self.vcpu_count as usize,
                limit: amla_core::vm_state::MAX_VCPUS,
            }
            .into());
        }
        Ok(())
    }

    /// Every pmem disk must have at least one image.
    /// `overlay_upper_tag` requires `overlay_target` and a matching `FsConfig`.
    fn validate_pmem_disks(&self) -> crate::Result<()> {
        use crate::ConfigError;
        for (i, disk) in self.pmem_disks.iter().enumerate() {
            if disk.images.is_empty() {
                return Err(ConfigError::EmptyPmemDisk { index: i }.into());
            }
            checked_pmem_disk_data_size(i, disk)?;
            if disk.overlay_target.as_ref().is_some_and(GuestPath::is_root) {
                return Err(ConfigError::OverlayTargetRoot { disk_index: i }.into());
            }
            if let Some(ref tag) = disk.overlay_upper_tag {
                if disk.overlay_target.is_none() {
                    return Err(ConfigError::UpperTagWithoutOverlay { index: i }.into());
                }
                if let Some(first) = self
                    .pmem_disks
                    .iter()
                    .take(i)
                    .position(|other| other.overlay_upper_tag.as_ref() == Some(tag))
                {
                    return Err(ConfigError::DuplicateOverlayUpperTag {
                        tag: tag.as_str().to_owned(),
                        first,
                        second: i,
                    }
                    .into());
                }
                if self.fs.as_ref().is_none_or(|f| f.tag != *tag) {
                    return Err(ConfigError::UnknownOverlayUpperTag {
                        index: i,
                        tag: tag.as_str().to_owned(),
                    }
                    .into());
                }
            }
            if disk.overlay_target.is_none() {
                for (image_index, image) in disk.images.iter().enumerate() {
                    if image.mount_path.is_none() {
                        return Err(ConfigError::PmemImageMissingMountPath {
                            disk_index: i,
                            image_index,
                        }
                        .into());
                    }
                }
            } else {
                for (image_index, image) in disk.images.iter().enumerate() {
                    if image.mount_path.is_some() {
                        return Err(ConfigError::PmemImageMountPathWithOverlay {
                            disk_index: i,
                            image_index,
                        }
                        .into());
                    }
                }
            }
        }
        Ok(())
    }

    /// At most one device can be the root filesystem (`mount_path == "/"`).
    fn validate_root_count(&self) -> crate::Result<()> {
        use crate::ConfigError;
        let mut root_count = 0usize;
        for disk in &self.pmem_disks {
            if let Some(target) = &disk.overlay_target {
                root_count += usize::from(target.is_root());
            } else {
                root_count += disk
                    .images
                    .iter()
                    .filter(|img| img.mount_path.as_ref().is_some_and(GuestPath::is_root))
                    .count();
            }
        }
        if self.fs.as_ref().is_some_and(|f| {
            f.mount_path.is_root() && !self.virtiofs_tag_consumed_by_overlay(&f.tag)
        }) {
            root_count += 1;
        }
        if root_count > 1 {
            return Err(ConfigError::MultipleRootDevices { count: root_count }.into());
        }
        Ok(())
    }

    /// Effective guest mount targets must be unique.
    fn validate_effective_mount_paths(&self) -> crate::Result<()> {
        let mut seen = BTreeMap::<String, String>::new();

        for (disk_index, disk) in self.pmem_disks.iter().enumerate() {
            if let Some(target) = &disk.overlay_target {
                insert_effective_mount_path(
                    &mut seen,
                    target,
                    format!("pmem_disks[{disk_index}].overlay_target"),
                )?;
            } else {
                for (image_index, image) in disk.images.iter().enumerate() {
                    if let Some(path) = &image.mount_path {
                        insert_effective_mount_path(
                            &mut seen,
                            path,
                            format!("pmem_disks[{disk_index}].images[{image_index}].mount_path"),
                        )?;
                    }
                }
            }
        }

        if let Some(fs) = &self.fs
            && !self.virtiofs_tag_consumed_by_overlay(&fs.tag)
        {
            insert_effective_mount_path(&mut seen, &fs.mount_path, String::from("fs.mount_path"))?;
        }

        Ok(())
    }

    /// Device layout must fit within both MMIO slots and IRQ capacity.
    fn validate_device_layout(&self) -> crate::Result<()> {
        use crate::ConfigError;
        let layout = crate::devices::DeviceLayout::from_config(self)?;
        let max = crate::devices::max_active_device_slots().min(amla_virtio_mmio::NUM_DEVICES);
        if layout.kinds().len() > max {
            return Err(ConfigError::TooManyDevices {
                count: layout.kinds().len(),
                max,
            }
            .into());
        }
        let _queue_wakes = crate::devices::QueueWakeMap::new(&layout)?;
        Ok(())
    }

    fn validate_net(&self) -> crate::Result<()> {
        use crate::ConfigError;
        if let Some(net) = self.net.as_ref()
            && !(1..=amla_virtio_net::MAX_QUEUE_PAIRS).contains(&net.queue_pairs)
        {
            return Err(ConfigError::NetQueuePairsOutOfRange {
                value: net.queue_pairs,
                max: amla_virtio_net::MAX_QUEUE_PAIRS,
            }
            .into());
        }
        Ok(())
    }

    /// Return whether a configured virtiofs tag is consumed as an overlay upper.
    pub(crate) fn virtiofs_tag_consumed_by_overlay(&self, tag: &VirtioFsTag) -> bool {
        self.pmem_disks.iter().any(|disk| {
            disk.overlay_target.is_some() && disk.overlay_upper_tag.as_ref() == Some(tag)
        })
    }
}

fn insert_effective_mount_path(
    seen: &mut BTreeMap<String, String>,
    path: &GuestPath,
    owner: String,
) -> crate::Result<()> {
    if path.is_root() {
        return Ok(());
    }
    if let Some(first) = seen.insert(path.as_str().to_owned(), owner.clone()) {
        return Err(crate::ConfigError::DuplicateMountPath {
            path: path.as_str().to_owned(),
            first,
            second: owner,
        }
        .into());
    }
    Ok(())
}

fn checked_pmem_disk_data_size(disk_index: usize, disk: &PmemDiskConfig) -> crate::Result<u64> {
    use crate::ConfigError;

    let max_images = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    if disk.images.len() > max_images {
        return Err(ConfigError::PmemDiskSizeInvalid {
            disk_index,
            size: u64::MAX,
            reason: String::from("image count exceeds u32::MAX"),
        }
        .into());
    }

    let mut total = 0u64;
    for (image_index, image) in disk.images.iter().enumerate() {
        if image.image_size == 0 {
            return Err(ConfigError::PmemImageSizeInvalid {
                disk_index,
                image_index,
                image_size: image.image_size,
                reason: String::from("must be greater than zero"),
            }
            .into());
        }
        let aligned = checked_host_page_align(image.image_size).ok_or_else(|| {
            ConfigError::PmemImageSizeInvalid {
                disk_index,
                image_index,
                image_size: image.image_size,
                reason: String::from("overflows host page alignment"),
            }
        })?;
        total = total
            .checked_add(aligned)
            .ok_or_else(|| ConfigError::PmemDiskSizeInvalid {
                disk_index,
                size: total,
                reason: format!("adding image {image_index} overflows u64"),
            })?;
    }

    let Some(geom) = amla_core::vm_state::pfn::PmemGeometry::checked_compute(
        total,
        amla_core::vm_state::pfn::GUEST_PAGE_SIZE,
    ) else {
        return Err(ConfigError::PmemDiskSizeInvalid {
            disk_index,
            size: total,
            reason: String::from("PFN geometry overflows"),
        }
        .into());
    };
    if amla_core::vm_state::checked_section_align(geom.total).is_none() {
        return Err(ConfigError::PmemDiskSizeInvalid {
            disk_index,
            size: total,
            reason: String::from("section-aligned PMEM size overflows"),
        }
        .into());
    }
    Ok(total)
}

fn checked_host_page_align(size: u64) -> Option<u64> {
    let page_size = u64::try_from(amla_mem::page_size()).ok()?;
    Some(size.checked_add(page_size - 1)? & !(page_size - 1))
}

fn validate_virtiofs_tag(tag: &str) -> Result<(), crate::ConfigError> {
    use crate::ConfigError;

    if tag.is_empty() {
        return Err(ConfigError::InvalidVirtioFsTag {
            value: tag.to_owned(),
            reason: String::from("must not be empty"),
        });
    }
    let tag_len = tag.len();
    if tag_len > VIRTIO_FS_TAG_MAX_BYTES {
        return Err(ConfigError::InvalidVirtioFsTag {
            value: tag.to_owned(),
            reason: format!(
                "length ({tag_len} bytes) exceeds virtio-fs metadata {VIRTIO_FS_TAG_MAX_BYTES}-byte limit"
            ),
        });
    }
    if let Some(byte) = tag.bytes().find(|b| *b == b'\0' || b.is_ascii_whitespace()) {
        return Err(ConfigError::InvalidVirtioFsTag {
            value: tag.to_owned(),
            reason: format!("contains disallowed byte {byte:#04x}"),
        });
    }
    if let Some(byte) = tag
        .bytes()
        .find(|b| !b.is_ascii_alphanumeric() && !matches!(*b, b'.' | b'_' | b'-'))
    {
        return Err(ConfigError::InvalidVirtioFsTag {
            value: tag.to_owned(),
            reason: format!(
                "contains unsupported byte {byte:#04x}; allowed: ASCII alphanumeric, '.', '_', '-'"
            ),
        });
    }
    Ok(())
}

/// Validate canonical absolute guest path syntax shared by public path types.
pub fn validate_guest_absolute_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(String::from("must not be empty"));
    }
    if !path.starts_with('/') {
        return Err(String::from("must be absolute"));
    }
    if let Some(ch) = path.chars().find(|ch| ch.is_control()) {
        return Err(format!("contains control character {:#04x}", u32::from(ch)));
    }
    if path != "/" {
        if path.ends_with('/') {
            return Err(String::from("must not have a trailing slash"));
        }
        for segment in path.split('/').skip(1) {
            if segment.is_empty() {
                return Err(String::from("must not contain empty path segments"));
            }
            if matches!(segment, "." | "..") {
                return Err(String::from("must not contain '.' or '..' path segments"));
            }
        }
    }
    Ok(())
}

fn validate_guest_path(path: &str) -> Result<(), crate::ConfigError> {
    use crate::ConfigError;

    validate_guest_absolute_path(path).map_err(|reason| ConfigError::InvalidGuestPath {
        value: path.to_owned(),
        reason,
    })?;
    if path.len() > GUEST_PATH_MAX_BYTES {
        return Err(ConfigError::InvalidGuestPath {
            value: path.to_owned(),
            reason: format!(
                "is too long for the {GUEST_PATH_MAX_BYTES}-byte device metadata field"
            ),
        });
    }
    if let Some(ch) = path.chars().find(|ch| matches!(ch, ':' | ',')) {
        return Err(ConfigError::InvalidGuestPath {
            value: path.to_owned(),
            reason: format!("contains overlay option delimiter {ch:?}"),
        });
    }
    Ok(())
}

fn validate_cmdline_atom(atom: &str) -> Result<(), crate::ConfigError> {
    use crate::ConfigError;

    if atom.is_empty() {
        return Err(ConfigError::CmdlineExtraInvalid {
            reason: String::from("atom must not be empty"),
        });
    }
    if let Some(byte) = atom
        .bytes()
        .find(|b| *b == b'\0' || b.is_ascii_whitespace())
    {
        return Err(ConfigError::CmdlineExtraInvalid {
            reason: format!("atom {atom:?} contains disallowed byte {byte:#04x}"),
        });
    }
    Ok(())
}

fn reject_reserved_cmdline_key(atom: &str) -> Result<(), crate::ConfigError> {
    use crate::ConfigError;

    let key = atom.split_once('=').map_or(atom, |(k, _)| k);
    if RESERVED_CMDLINE_KEYS.contains(&key) {
        return Err(ConfigError::CmdlineExtraInvalid {
            reason: format!("reserved kernel cmdline key: {key}"),
        });
    }
    Ok(())
}

/// Parse `cmdline_extra` into strongly typed atoms.
///
/// NUL and newlines (`\n`, `\r`) are forbidden before splitting: the cmdline is
/// assembled as a single NUL-terminated line, so either byte would truncate or
/// split it into two.
fn parse_cmdline_extra(extra: &str) -> Result<Vec<KernelCmdlineAtom>, crate::ConfigError> {
    use crate::ConfigError;

    if let Some(byte) = extra.bytes().find(|b| matches!(b, b'\0' | b'\n' | b'\r')) {
        return Err(ConfigError::CmdlineExtraInvalid {
            reason: format!("contains disallowed byte {byte:#04x}"),
        });
    }
    extra
        .split_ascii_whitespace()
        .map(KernelCmdlineAtom::new)
        .collect()
}

/// Reject `cmdline_extra` atoms that would collide with keys this crate sets
/// automatically.
fn validate_cmdline_extra(extra: &[KernelCmdlineAtom]) -> Result<(), crate::ConfigError> {
    for atom in extra {
        reject_reserved_cmdline_key(atom.as_str())?;
    }
    Ok(())
}

pub fn join_cmdline_atoms(atoms: &[KernelCmdlineAtom]) -> String {
    atoms
        .iter()
        .map(KernelCmdlineAtom::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_config_defaults() {
        let config = VmConfig::default();
        assert_eq!(config.memory_mb, 256);
        assert_eq!(config.vcpu_count, 1);
        assert!(config.net.is_none());
        assert!(config.fs.is_none());
    }

    #[test]
    fn test_vm_config_builder_chain() {
        let config = VmConfig::default().memory_mb(512).vcpu_count(4);
        assert_eq!(config.memory_mb, 512);
        assert_eq!(config.vcpu_count, 4);
    }

    #[test]
    fn test_net_config_default() {
        let net = NetConfig::default();
        assert!(net.mac_address.is_none());
        assert_eq!(net.guest_mac(), DEFAULT_GUEST_MAC);
    }

    #[test]
    fn test_net_config_mac() {
        let mac = [1, 2, 3, 4, 5, 6];
        let net = NetConfig::default().mac(mac);
        assert_eq!(net.mac_address, Some(mac));
        assert_eq!(net.guest_mac(), mac);
    }

    #[test]
    fn test_fs_config_new() {
        let fs = FsConfig::new(
            VirtioFsTag::new("myfs").unwrap(),
            GuestPath::new("/mnt").unwrap(),
        );
        assert_eq!(fs.tag.as_str(), "myfs");
        assert_eq!(fs.mount_path.as_str(), "/mnt");
    }

    #[test]
    fn test_fs_config_root() {
        let fs = FsConfig::root(VirtioFsTag::new("rootfs").unwrap());
        assert_eq!(fs.mount_path.as_str(), "/");
        assert_eq!(fs.tag.as_str(), "rootfs");
    }

    #[test]
    fn test_validate_accepts_max_length_virtiofs_tag() {
        let tag = "a".repeat(VIRTIO_FS_TAG_MAX_BYTES);
        let config = VmConfig::default().fs(FsConfig::try_new(tag, "/mnt").unwrap());
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_create_accepts_max_storable_virtiofs_tag() {
        let tag = "a".repeat(VIRTIO_FS_TAG_MAX_BYTES);
        let config = VmConfig::default().fs(FsConfig::try_new(tag, "/mnt").unwrap());

        crate::VirtualMachine::create(config).await.unwrap();
    }

    #[test]
    fn test_validate_rejects_overlong_virtiofs_tag() {
        let tag = "a".repeat(VIRTIO_FS_TAG_MAX_BYTES + 1);
        let err = FsConfig::try_new(tag, "/mnt").unwrap_err().to_string();
        assert!(err.contains("virtiofs tag"), "{err}");
        assert!(err.contains("35-byte"), "{err}");
    }

    #[test]
    fn test_virtiofs_tag_rejects_cmdline_delimiters() {
        for tag in [
            "", "bad tag", "bad\ntag", "bad\0tag", "bad/tag", "bad=tag", "bad:tag",
        ] {
            let err = VirtioFsTag::new(tag).unwrap_err().to_string();
            assert!(err.contains("virtiofs tag"), "{err}");
        }
    }

    #[test]
    fn test_guest_path_rejects_parser_hazards() {
        for path in ["", "relative", "/bad:path", "/bad,path", "/bad\npath"] {
            let err = GuestPath::new(path).unwrap_err().to_string();
            assert!(err.contains("guest path"), "{err}");
        }
    }

    #[test]
    fn test_guest_path_requires_canonical_absolute_path() {
        for path in [
            "/.",
            "/..",
            "/mnt/.",
            "/mnt/..",
            "/mnt/../etc",
            "/mnt//cache",
            "/mnt/cache/",
        ] {
            let err = GuestPath::new(path).unwrap_err().to_string();
            assert!(err.contains("guest path"), "{err}");
        }
    }

    #[test]
    fn test_guest_path_rejects_overlong_device_metadata_path() {
        let valid = format!("/{}", "a".repeat(GUEST_PATH_MAX_BYTES - 1));
        assert_eq!(GuestPath::new(&valid).unwrap().as_str(), valid);

        let invalid = format!("/{}", "a".repeat(GUEST_PATH_MAX_BYTES));
        let err = GuestPath::new(invalid).unwrap_err().to_string();
        assert!(err.contains("device metadata"), "{err}");
    }

    #[test]
    fn test_cmdline_extra_parses_atoms_and_rejects_reserved_keys() {
        let config = VmConfig::default().cmdline_extra([
            KernelCmdlineAtom::new("net_test_url=http://127.0.0.1").unwrap(),
            KernelCmdlineAtom::new("net_no_verify=1").unwrap(),
        ]);
        assert_eq!(config.cmdline_extra.len(), 2);
        assert_eq!(
            config.cmdline_extra[0].as_str(),
            "net_test_url=http://127.0.0.1"
        );

        let err = VmConfig::default()
            .try_cmdline_extra("root=/dev/vda")
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved kernel cmdline key: root"), "{err}");
    }

    #[test]
    fn test_pmem_disk_builder() {
        let config = VmConfig::default()
            .pmem_disk(100, GuestPath::new("/app").unwrap())
            .pmem_disk(200, GuestPath::new("/data").unwrap());
        assert_eq!(config.pmem_disks.len(), 2);
        assert_eq!(
            config.pmem_disks[0].images[0]
                .mount_path
                .as_ref()
                .unwrap()
                .as_str(),
            "/app"
        );
        assert_eq!(
            config.pmem_disks[1].images[0]
                .mount_path
                .as_ref()
                .unwrap()
                .as_str(),
            "/data"
        );
        assert_eq!(config.pmem_disks[0].images[0].image_size, 100);
        assert_eq!(config.pmem_disks[1].images[0].image_size, 200);
    }

    #[test]
    fn test_pmem_disk_config_serde() {
        let config = VmConfig::default().pmem_disk(50, GuestPath::new("/app").unwrap());
        let json = serde_json::to_string(&config).unwrap();
        let restored: VmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pmem_disks.len(), 1);
        assert_eq!(
            restored.pmem_disks[0].images[0]
                .mount_path
                .as_ref()
                .unwrap()
                .as_str(),
            "/app"
        );
        assert_eq!(restored.pmem_disks[0].images[0].image_size, 50);
    }

    #[test]
    fn test_validate_default_ok() {
        assert!(VmConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_zero_memory() {
        let config = VmConfig::default().memory_mb(0);
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("memory_mb"), "{err}");
    }

    #[test]
    fn test_validate_rejects_zero_vcpus() {
        let config = VmConfig::default().vcpu_count(0);
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("vcpu_count"), "{err}");
    }

    #[test]
    fn test_validate_rejects_overflow_memory_mb() {
        // usize::MAX / (1024*1024) doesn't overflow when multiplied back,
        // so use a value that's aligned but still causes checked_mul to fail.
        // (usize::MAX - 1) / (1024*1024) + BLOCK_SIZE_MB overflows because
        // adding BLOCK_SIZE_MB pushes it past the division boundary.
        let huge = ((usize::MAX / (1024 * 1024)) + 1) & !(amla_core::BLOCK_SIZE_MB - 1);
        if huge.checked_mul(1024 * 1024).is_some() {
            // Can't construct an overflowing aligned value on this platform.
            return;
        }
        let config = VmConfig {
            memory_mb: huge,
            ..VmConfig::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("overflows"), "{err}");
    }

    #[test]
    fn test_vm_config_serde_roundtrip() {
        let config = VmConfig::default()
            .memory_mb(512)
            .vcpu_count(4)
            .net(NetConfig::default().mac([1, 2, 3, 4, 5, 6]))
            .fs(FsConfig::root(VirtioFsTag::new("rootfs").unwrap()));

        let json = serde_json::to_string(&config).unwrap();
        let restored: VmConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.memory_mb, 512);
        assert_eq!(restored.vcpu_count, 4);
        assert_eq!(
            restored.net.as_ref().unwrap().mac_address,
            Some([1, 2, 3, 4, 5, 6])
        );
        assert_eq!(restored.fs.as_ref().unwrap().tag.as_str(), "rootfs");
        assert_eq!(restored.fs.as_ref().unwrap().mount_path.as_str(), "/");
    }

    #[test]
    fn test_vm_config_serde_defaults() {
        let config = VmConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: VmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.memory_mb, 256);
        assert_eq!(restored.vcpu_count, 1);
    }

    #[test]
    fn test_validate_rejects_multiple_root_devices() {
        let config = VmConfig::default()
            .pmem_root(100)
            .fs(FsConfig::root(VirtioFsTag::new("rootfs").unwrap()));
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("multiple root"), "{err}");
    }

    #[test]
    fn test_validate_rejects_overlay_target_root() {
        let config = VmConfig::default()
            .pmem_overlay(vec![PmemImageConfig::overlay(100)], GuestPath::root());

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("overlay_target"), "{err}");
        assert!(err.contains('/'), "{err}");
    }

    #[test]
    fn test_validate_single_root_ok() {
        let config = VmConfig::default().pmem_root(100);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_duplicate_effective_mount_paths() {
        let config = VmConfig::default()
            .pmem_disk(100, GuestPath::new("/data").unwrap())
            .fs(FsConfig::try_new("hostfs", "/data").unwrap());

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate guest mount path"), "{err}");
        assert!(err.contains("/data"), "{err}");
    }

    #[test]
    fn test_validate_rejects_duplicate_overlay_upper_tags() {
        let upper = VirtioFsTag::new("upper").unwrap();
        let config = VmConfig::default()
            .fs(FsConfig::new(
                upper.clone(),
                GuestPath::new("/upper").unwrap(),
            ))
            .pmem_overlay_with_upper(
                vec![PmemImageConfig::overlay(100)],
                GuestPath::new("/app").unwrap(),
                upper.clone(),
            )
            .pmem_overlay_with_upper(
                vec![PmemImageConfig::overlay(100)],
                GuestPath::new("/data").unwrap(),
                upper,
            );

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate overlay upper tag"), "{err}");
        assert!(err.contains("upper"), "{err}");
    }

    #[test]
    fn test_validate_rejects_empty_pmem_disk() {
        let mut config = VmConfig::default();
        config.pmem_disks.push(PmemDiskConfig {
            images: vec![],
            overlay_target: None,
            overlay_upper_tag: None,
        });
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("no images"), "{err}");
    }

    #[test]
    fn test_validate_rejects_pmem_image_size_overflow() {
        let config = VmConfig::default().pmem_disk(u64::MAX, GuestPath::new("/data").unwrap());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("image_size"), "{err}");
        assert!(err.contains("overflows"), "{err}");
    }

    #[test]
    fn test_validate_rejects_zero_pmem_image_size() {
        let config = VmConfig::default().pmem_disk(0, GuestPath::new("/data").unwrap());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("image_size=0"), "{err}");
        assert!(err.contains("greater than zero"), "{err}");
    }

    #[test]
    fn test_validate_rejects_zero_overlay_pmem_image_size() {
        let config = VmConfig::default().pmem_overlay(
            vec![PmemImageConfig::overlay(0)],
            GuestPath::new("/data").unwrap(),
        );
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("image_size=0"), "{err}");
        assert!(err.contains("greater than zero"), "{err}");
    }

    #[test]
    fn test_validate_rejects_overlay_image_mount_path() {
        let mut config = VmConfig::default();
        config.pmem_disks.push(PmemDiskConfig {
            images: vec![PmemImageConfig::new(
                4096,
                GuestPath::new("/ignored").unwrap(),
            )],
            overlay_target: Some(GuestPath::new("/data").unwrap()),
            overlay_upper_tag: None,
        });

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("mount_path"), "{err}");
        assert!(err.contains("overlay_target"), "{err}");
    }

    #[test]
    fn test_validate_rejects_pmem_image_without_mount_path_outside_overlay() {
        let config = VmConfig::default().pmem_packed(vec![PmemImageConfig::overlay(4096)]);
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("requires mount_path"), "{err}");
    }

    #[test]
    fn test_pmem_root_is_sugar_for_pmem_disk_slash() {
        let config = VmConfig::default().pmem_root(100);
        assert_eq!(config.pmem_disks.len(), 1);
        assert_eq!(
            config.pmem_disks[0].images[0]
                .mount_path
                .as_ref()
                .unwrap()
                .as_str(),
            "/"
        );
    }

    // ── vcpu_count ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_rejects_vcpu_exceeds_limit() {
        let config = VmConfig {
            vcpu_count: amla_core::vm_state::MAX_VCPUS as u32 + 1,
            ..VmConfig::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("MAX_VCPUS"), "{err}");
    }

    #[test]
    fn test_validate_vcpu_at_limit_ok() {
        let config = VmConfig::default().vcpu_count(amla_core::vm_state::MAX_VCPUS as u32);
        assert!(config.validate().is_ok());
    }

    // ── memory alignment and minimum ─────────────────────────────────

    #[test]
    fn test_validate_rejects_memory_below_minimum() {
        let config = VmConfig {
            memory_mb: 64,
            ..VmConfig::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("MIN_MEMORY_MB"), "{err}");
    }

    #[test]
    fn test_validate_rejects_unaligned_memory_mb() {
        let config = VmConfig {
            memory_mb: 129,
            ..VmConfig::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not aligned"), "{err}");
    }

    #[test]
    fn test_validate_accepts_aligned_memory() {
        let config = VmConfig::default().memory_mb(128);
        assert!(config.validate().is_ok());
    }
}
