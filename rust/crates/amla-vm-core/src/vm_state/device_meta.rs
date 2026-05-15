// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Device metadata slots for self-describing device layout in the mmap.
//!
//! Each device slot has a 128-byte metadata entry that records the device kind,
//! tag (for virtiofs), and mount path. This enables restore without needing the
//! original `VmConfig`, and allows the guest agent to discover mount instructions
//! from the mmap.

use bytemuck::{Pod, Zeroable};

use super::header::DEVICE_META_SLOT_SIZE;

const TAG_FIELD: &str = "device metadata tag";
const MOUNT_PATH_FIELD: &str = "device metadata mount path";
const TAG_MAX_BYTES: usize = 35;
const MOUNT_PATH_MAX_BYTES: usize = 83;

/// Validation error for durable device metadata slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceMetaError {
    /// The field exceeds the fixed-size, NUL-terminated storage.
    #[error("{field} is too long: {len} bytes > max {max}")]
    TooLong {
        /// Field name.
        field: &'static str,
        /// Provided byte length.
        len: usize,
        /// Maximum byte length excluding the NUL terminator.
        max: usize,
    },
    /// Input strings may not contain interior NUL bytes.
    #[error("{field} contains a NUL byte")]
    ContainsNul {
        /// Field name.
        field: &'static str,
    },
    /// The fixed-size field has no NUL terminator.
    #[error("{field} is not NUL-terminated")]
    MissingNul {
        /// Field name.
        field: &'static str,
    },
    /// Bytes after the first NUL terminator must be zero for canonical state.
    #[error("{field} has nonzero bytes after the NUL terminator")]
    TrailingGarbage {
        /// Field name.
        field: &'static str,
    },
    /// The non-NUL prefix is not valid UTF-8.
    #[error("{field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Field name.
        field: &'static str,
    },
    /// Reserved metadata bytes are not zero.
    #[error("reserved device metadata bytes are nonzero")]
    ReservedNonzero,
    /// Active metadata kind must match the durable header.
    #[error("device metadata kind {actual} does not match header kind {expected}")]
    KindMismatch {
        /// Durable header kind.
        expected: u8,
        /// Metadata slot kind.
        actual: u8,
    },
    /// Inactive slots must be exactly zero.
    #[error("inactive device metadata slot is nonzero")]
    InactiveSlotNonzero,
}

/// Validated virtiofs tag ready to be copied into durable device metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceMetaTag<'a>(&'a str);

impl<'a> DeviceMetaTag<'a> {
    /// Validate a tag against the fixed durable metadata representation.
    pub fn new(value: &'a str) -> Result<Self, DeviceMetaError> {
        validate_input(value, TAG_MAX_BYTES, TAG_FIELD)?;
        Ok(Self(value))
    }

    /// Return the validated tag string.
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// Validated mount path ready to be copied into durable device metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceMetaMountPath<'a>(&'a str);

impl<'a> DeviceMetaMountPath<'a> {
    /// Validate a mount path against the fixed durable metadata representation.
    pub fn new(value: &'a str) -> Result<Self, DeviceMetaError> {
        validate_input(value, MOUNT_PATH_MAX_BYTES, MOUNT_PATH_FIELD)?;
        Ok(Self(value))
    }

    /// Return the validated mount path string.
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// Metadata for a single device slot in the mmap.
///
/// 128 bytes, `repr(C)`, `Pod + Zeroable`. A zeroed slot represents a
/// reserved (unused) device.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct DeviceMetaSlot {
    kind: u8,
    flags: u8,
    reserved: [u8; 6],
    tag: [u8; 36],
    mount_path: [u8; 84],
}

// Compile-time size check.
const _: () = assert!(core::mem::size_of::<DeviceMetaSlot>() == DEVICE_META_SLOT_SIZE);

impl DeviceMetaSlot {
    /// Construct a canonical empty metadata slot for `kind`.
    pub fn new(kind: u8) -> Self {
        Self {
            kind,
            ..Self::zeroed()
        }
    }

    /// Return the durable device kind code.
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// Reset this slot to canonical empty metadata for `kind`.
    pub fn reset(&mut self, kind: u8) {
        *self = Self::new(kind);
    }

    /// Set the device tag from a validated tag token.
    pub fn set_tag(&mut self, tag: DeviceMetaTag<'_>) {
        write_canonical_field(&mut self.tag, tag.as_str());
    }

    /// Validate and set the device tag exactly, without truncation.
    pub fn set_tag_exact(&mut self, value: &str) -> Result<(), DeviceMetaError> {
        self.set_tag(DeviceMetaTag::new(value)?);
        Ok(())
    }

    /// Read the canonical device tag.
    pub fn tag_str(&self) -> Result<&str, DeviceMetaError> {
        read_canonical_field(&self.tag, TAG_FIELD)
    }

    /// Set the mount path from a validated mount-path token.
    pub fn set_mount_path(&mut self, path: DeviceMetaMountPath<'_>) {
        write_canonical_field(&mut self.mount_path, path.as_str());
    }

    /// Validate and set the mount path exactly, without truncation.
    pub fn set_mount_path_exact(&mut self, value: &str) -> Result<(), DeviceMetaError> {
        self.set_mount_path(DeviceMetaMountPath::new(value)?);
        Ok(())
    }

    /// Read the canonical mount path.
    pub fn mount_path_str(&self) -> Result<&str, DeviceMetaError> {
        read_canonical_field(&self.mount_path, MOUNT_PATH_FIELD)
    }

    /// Validate this active slot against the durable header kind.
    pub fn validate_active(&self, expected_kind: u8) -> Result<(), DeviceMetaError> {
        if self.kind != expected_kind {
            return Err(DeviceMetaError::KindMismatch {
                expected: expected_kind,
                actual: self.kind,
            });
        }
        if self.flags != 0 || self.reserved.iter().any(|&byte| byte != 0) {
            return Err(DeviceMetaError::ReservedNonzero);
        }
        self.tag_str()?;
        self.mount_path_str()?;
        Ok(())
    }

    /// Validate this inactive slot is exactly zero.
    pub fn validate_inactive(&self) -> Result<(), DeviceMetaError> {
        if bytemuck::bytes_of(self).iter().any(|&byte| byte != 0) {
            return Err(DeviceMetaError::InactiveSlotNonzero);
        }
        Ok(())
    }
}

fn validate_input(value: &str, max_len: usize, field: &'static str) -> Result<(), DeviceMetaError> {
    let len = value.len();
    if len > max_len {
        return Err(DeviceMetaError::TooLong {
            field,
            len,
            max: max_len,
        });
    }
    if value.as_bytes().contains(&0) {
        return Err(DeviceMetaError::ContainsNul { field });
    }
    Ok(())
}

fn write_canonical_field(dst: &mut [u8], value: &str) {
    dst.fill(0);
    dst[..value.len()].copy_from_slice(value.as_bytes());
}

fn read_canonical_field<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> Result<&'a str, DeviceMetaError> {
    let nul = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(DeviceMetaError::MissingNul { field })?;
    if bytes[nul + 1..].iter().any(|&byte| byte != 0) {
        return Err(DeviceMetaError::TrailingGarbage { field });
    }
    core::str::from_utf8(&bytes[..nul]).map_err(|_| DeviceMetaError::InvalidUtf8 { field })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use bytemuck::Zeroable;

    #[test]
    fn test_slot_zeroed_is_empty() {
        let slot = DeviceMetaSlot::zeroed();
        assert_eq!(slot.kind(), 0);
        assert_eq!(slot.tag_str().unwrap(), "");
        assert_eq!(slot.mount_path_str().unwrap(), "");
    }

    #[test]
    fn test_set_tag_and_mount_path() {
        let mut slot = DeviceMetaSlot::zeroed();
        slot.set_tag(DeviceMetaTag::new("myfs").unwrap());
        slot.set_mount_path(DeviceMetaMountPath::new("/data/shared").unwrap());
        assert_eq!(slot.tag_str().unwrap(), "myfs");
        assert_eq!(slot.mount_path_str().unwrap(), "/data/shared");
    }

    #[test]
    fn test_tag_rejects_truncation() {
        let mut slot = DeviceMetaSlot::zeroed();
        let long_tag = "a".repeat(100);
        assert!(matches!(
            slot.set_tag_exact(&long_tag),
            Err(DeviceMetaError::TooLong { .. })
        ));
        assert_eq!(slot.tag_str().unwrap(), "");
    }

    #[test]
    fn test_mount_path_rejects_truncation() {
        let mut slot = DeviceMetaSlot::zeroed();
        let long_path = "/".to_string() + &"a".repeat(200);
        assert!(matches!(
            slot.set_mount_path_exact(&long_path),
            Err(DeviceMetaError::TooLong { .. })
        ));
        assert_eq!(slot.mount_path_str().unwrap(), "");
    }

    #[test]
    fn test_root_mount_path() {
        let mut slot = DeviceMetaSlot::zeroed();
        slot.set_mount_path_exact("/").unwrap();
        assert_eq!(slot.mount_path_str().unwrap(), "/");
    }

    #[test]
    fn shorter_set_clears_previous_tail() {
        let mut slot = DeviceMetaSlot::zeroed();
        slot.set_tag_exact("abcdef").unwrap();
        slot.set_tag_exact("a").unwrap();
        assert_eq!(slot.tag_str().unwrap(), "a");
        assert!(slot.tag[2..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn canonical_reader_rejects_trailing_garbage() {
        let mut slot = DeviceMetaSlot::zeroed();
        slot.tag[0] = 0;
        slot.tag[1] = b'x';
        assert!(matches!(
            slot.tag_str(),
            Err(DeviceMetaError::TrailingGarbage { .. })
        ));
    }

    #[test]
    fn canonical_reader_rejects_invalid_utf8() {
        let mut slot = DeviceMetaSlot::zeroed();
        slot.tag[0] = 0xff;
        slot.tag[1] = 0;
        assert!(matches!(
            slot.tag_str(),
            Err(DeviceMetaError::InvalidUtf8 { .. })
        ));
    }
}
