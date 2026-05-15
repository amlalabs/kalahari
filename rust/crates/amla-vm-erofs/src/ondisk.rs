// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! EROFS on-disk format structures.
//!
//! All multi-byte fields are little-endian. Structures are `#[repr(C, packed)]`
//! to match the exact on-disk layout, and derive `bytemuck::Pod` for safe
//! byte-level reinterpretation without `unsafe`.

#[cfg(not(target_endian = "little"))]
compile_error!("amla-erofs on-disk structs assume little-endian byte order");

use bytemuck::{Pod, Zeroable};

use crate::{BLOCK_SIZE_BITS, EROFS_MAGIC};

// --- Inode format and layout constants ---
//
// EROFS has two independent encoding axes:
//   1. **Inode format** (bit 0 of `i_format`): compact (0) vs extended (1).
//   2. **Data layout** (bits 1..3 of `i_format`): how file data is stored.
//
// `EROFS_INODE_FLAT_COMPACT` and `EROFS_INODE_FLAT_PLAIN` both have value 0
// because they describe different fields — inode format vs data layout.

/// Compact inode (32 bytes, no timestamps per inode).
pub const EROFS_INODE_FLAT_COMPACT: u16 = 0;

/// Data layout: contiguous blocks starting at `raw_blkaddr`.
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;
/// Data layout: tail-packed inline after the inode metadata.
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;
/// Data layout: chunk-based — file data lives at external block offsets.
pub const EROFS_INODE_CHUNK_BASED: u16 = 4;

// --- Chunk format constants ---

/// Mask for chunk size bits in `ChunkInfo::format` (log2 of chunk size).
pub const EROFS_CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001F;
/// Flag: chunk indices follow the inode in the metadata area.
pub const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;

// --- Feature flags ---

/// Incompatible feature: image contains chunk-based files.
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;

// --- File type constants (match dirent `file_type`) ---
pub const EROFS_FT_REG_FILE: u8 = 1;
pub const EROFS_FT_DIR: u8 = 2;
pub const EROFS_FT_CHRDEV: u8 = 3;
pub const EROFS_FT_BLKDEV: u8 = 4;
pub const EROFS_FT_FIFO: u8 = 5;
pub const EROFS_FT_SOCK: u8 = 6;
pub const EROFS_FT_SYMLINK: u8 = 7;

/// EROFS superblock — 128 bytes at offset 1024.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct SuperBlock {
    pub magic: u32,              // 0xE0F5E1E2
    pub checksum: u32,           // CRC32 (unused in our MVP, set to 0)
    pub feature_compat: u32,     // compatible feature flags
    pub blkszbits: u8,           // log2(block_size), e.g. 12 for 4096
    pub sb_extslots: u8,         // extra superblock slots (0)
    pub root_nid: u16,           // root inode NID
    pub inos: u64,               // total inode count
    pub build_time: u64,         // image creation time (seconds since epoch)
    pub build_time_nsec: u32,    // nanoseconds part
    pub blocks: u32,             // total blocks in image
    pub meta_blkaddr: u32,       // block address of inode metadata area
    pub xattr_blkaddr: u32,      // block address of xattr area (unused, 0)
    pub uuid: [u8; 16],          // filesystem UUID (zeroed)
    pub volume_name: [u8; 16],   // volume label (zeroed)
    pub feature_incompat: u32,   // incompatible feature flags
    pub u1: u16,                 // union (unused)
    pub extra_devices: u16,      // number of extra devices (0)
    pub devt_slotoff: u16,       // device table slot offset (0)
    pub dirblkbits: u8,          // must be 0 (deprecated; kernel rejects non-zero)
    pub xattr_prefix_count: u8,  // xattr prefix count (0)
    pub xattr_prefix_start: u32, // xattr prefix start (0)
    pub packed_nid: u64,         // packed inode NID (unused, 0)
    pub reserved2: [u8; 24],     // reserved (zeroed)
}

const _: () = assert!(core::mem::size_of::<SuperBlock>() == 128);
const _: () = assert!(core::mem::align_of::<SuperBlock>() == 1);

impl SuperBlock {
    #[must_use]
    pub const fn new(root_nid: u16, inos: u64, blocks: u32, meta_blkaddr: u32) -> Self {
        Self {
            magic: EROFS_MAGIC,
            checksum: 0,
            feature_compat: 0,
            blkszbits: BLOCK_SIZE_BITS,
            sb_extslots: 0,
            root_nid,
            inos,
            build_time: 0,
            build_time_nsec: 0,
            blocks,
            meta_blkaddr,
            xattr_blkaddr: 0,
            uuid: [0; 16],
            volume_name: [0; 16],
            feature_incompat: 0,
            u1: 0,
            extra_devices: 0,
            devt_slotoff: 0,
            dirblkbits: 0,
            xattr_prefix_count: 0,
            xattr_prefix_start: 0,
            packed_nid: 0,
            reserved2: [0; 24],
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        data.get(..core::mem::size_of::<Self>())
            .and_then(|slice| bytemuck::try_from_bytes(slice).ok())
    }
}

/// Compact inode — 32 bytes.
///
/// NID (Node ID) = byte offset of this struct from the metadata area start,
/// divided by 32 (the inode slot size).
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct InodeCompact {
    /// Format: low 1 bit = compact(0), bits 1..3 = data layout
    pub i_format: u16,
    pub i_xattr_icount: u16,
    pub i_mode: u16,
    pub i_nlink: u16,
    pub i_size: u32,
    pub i_reserved: u32,
    /// For `FLAT_PLAIN`: starting block address of file data.
    /// For device nodes: rdev value (major/minor encoded).
    pub i_u: u32,
    pub i_ino: u32,
    pub i_uid: u16,
    pub i_gid: u16,
    pub i_reserved2: u32,
}

const _: () = assert!(core::mem::size_of::<InodeCompact>() == 32);
const _: () = assert!(core::mem::align_of::<InodeCompact>() == 1);

/// Extended inode — 64 bytes (with timestamps and 32-bit uid/gid).
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct InodeExtended {
    /// Format: low 1 bit = extended(1), bits 1..3 = data layout
    pub i_format: u16,
    pub i_xattr_icount: u16,
    pub i_mode: u16,
    _reserved: u16,
    pub i_size: u64,
    pub i_u: u32,
    pub i_ino: u32,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_mtime: u64,
    pub i_mtime_nsec: u32,
    pub i_nlink: u32,
    _reserved2: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<InodeExtended>() == 64);
const _: () = assert!(core::mem::align_of::<InodeExtended>() == 1);

impl InodeExtended {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        mode: u16,
        size: u64,
        nlink: u32,
        uid: u32,
        gid: u32,
        layout: u16,
        mtime: u64,
        mtime_nsec: u32,
    ) -> Self {
        // bit 0 = 1 (extended), bits 1..3 = data layout
        let i_format = (layout << 1) | 1;
        Self {
            i_format,
            i_xattr_icount: 0,
            i_mode: mode,
            _reserved: 0,
            i_size: size,
            i_u: 0,
            i_ino: 0,
            i_uid: uid,
            i_gid: gid,
            i_mtime: mtime,
            i_mtime_nsec: mtime_nsec,
            i_nlink: nlink,
            _reserved2: [0u8; 16],
        }
    }

    #[must_use]
    pub const fn data_layout(&self) -> u16 {
        (self.i_format >> 1) & 0x7
    }

    /// Block address for `FLAT_PLAIN`, or rdev for device nodes.
    #[must_use]
    pub const fn raw_blkaddr(&self) -> u32 {
        self.i_u
    }

    pub const fn set_raw_blkaddr(&mut self, addr: u32) {
        self.i_u = addr;
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        data.get(..core::mem::size_of::<Self>())
            .and_then(|slice| bytemuck::try_from_bytes(slice).ok())
    }
}

/// Inode slot size in bytes (NIDs are counted in slots)
pub const EROFS_INODE_SLOT_SIZE: u64 = 32;

impl InodeCompact {
    #[must_use]
    pub const fn new(mode: u16, size: u32, nlink: u16, uid: u16, gid: u16, layout: u16) -> Self {
        let i_format = (layout << 1) | EROFS_INODE_FLAT_COMPACT;
        Self {
            i_format,
            i_xattr_icount: 0,
            i_mode: mode,
            i_nlink: nlink,
            i_size: size,
            i_reserved: 0,
            i_u: 0,
            i_ino: 0,
            i_uid: uid,
            i_gid: gid,
            i_reserved2: 0,
        }
    }

    #[must_use]
    pub const fn data_layout(&self) -> u16 {
        (self.i_format >> 1) & 0x7
    }

    /// Block address for `FLAT_PLAIN`, or rdev for device nodes.
    #[must_use]
    pub const fn raw_blkaddr(&self) -> u32 {
        self.i_u
    }

    pub const fn set_raw_blkaddr(&mut self, addr: u32) {
        self.i_u = addr;
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        data.get(..core::mem::size_of::<Self>())
            .and_then(|slice| bytemuck::try_from_bytes(slice).ok())
    }
}

/// Directory entry header — 12 bytes.
///
/// Names follow contiguously after a block of dirent headers. The `nameoff`
/// field gives the byte offset within the directory block where this entry's
/// name starts. Name length is computed from the difference between consecutive
/// `nameoff` values (or end of block for the last entry).
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct Dirent {
    pub nid: u64,
    pub nameoff: u16,
    pub file_type: u8,
    pub reserved: u8,
}

const _: () = assert!(core::mem::size_of::<Dirent>() == 12);
const _: () = assert!(core::mem::align_of::<Dirent>() == 1);

impl Dirent {
    #[must_use]
    pub const fn new(nid: u64, nameoff: u16, file_type: u8) -> Self {
        Self {
            nid,
            nameoff,
            file_type,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        data.get(..core::mem::size_of::<Self>())
            .and_then(|slice| bytemuck::try_from_bytes(slice).ok())
    }
}

/// Chunk index entry — 8 bytes.
///
/// Each chunk of a chunk-based file has one of these, specifying which
/// device and block address the chunk's data lives at.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct ChunkIndex {
    /// Reserved, always 0.
    pub advise: u16,
    /// Back-end storage id (0 = primary device / same file).
    pub device_id: u16,
    /// Start block address on the device.
    pub blkaddr: u32,
}

const _: () = assert!(core::mem::size_of::<ChunkIndex>() == 8);
const _: () = assert!(core::mem::align_of::<ChunkIndex>() == 1);

impl ChunkIndex {
    #[must_use]
    pub const fn new(device_id: u16, blkaddr: u32) -> Self {
        Self {
            advise: 0,
            device_id,
            blkaddr,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        data.get(..core::mem::size_of::<Self>())
            .and_then(|slice| bytemuck::try_from_bytes(slice).ok())
    }
}

/// Device slot — 128 bytes.
///
/// Describes an extra device in multi-device EROFS images.
/// The device table follows the superblock at offset `devt_slotoff`.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct DeviceSlot {
    /// Total blocks on this device.
    pub blocks: u32,
    /// Mapped block address.
    pub mapped_blkaddr: u32,
    /// Reserved (zeroed).
    pub reserved: [u8; 120],
}

const _: () = assert!(core::mem::size_of::<DeviceSlot>() == 128);
const _: () = assert!(core::mem::align_of::<DeviceSlot>() == 1);

/// Convert `S_IFMT` mode bits to dirent `file_type`.
#[must_use]
pub const fn mode_to_file_type(mode: u16) -> u8 {
    match mode & 0o170_000 {
        0o100_000 => EROFS_FT_REG_FILE,
        0o040_000 => EROFS_FT_DIR,
        0o120_000 => EROFS_FT_SYMLINK,
        0o020_000 => EROFS_FT_CHRDEV,
        0o060_000 => EROFS_FT_BLKDEV,
        0o010_000 => EROFS_FT_FIFO,
        0o140_000 => EROFS_FT_SOCK,
        _ => 0,
    }
}

// ── Xattr on-disk structures ──────────────────────────────────────────────

/// Inline xattr header — 12 bytes, placed immediately after the inode struct
/// when `i_xattr_icount > 0`.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct XattrInodeHeader {
    pub h_reserved: u32,
    pub h_shared_count: u8,
    pub h_reserved2: [u8; 7],
}

const _: () = assert!(core::mem::size_of::<XattrInodeHeader>() == 12);

/// Xattr entry header — 4 bytes, followed by name suffix and value bytes.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct XattrEntry {
    /// Length of the name suffix (after stripping the well-known prefix).
    pub e_name_len: u8,
    /// Prefix index (1=user., 6=security., 7=system., 8=trusted., etc.)
    pub e_name_index: u8,
    /// Length of the value in bytes.
    pub e_value_size: u16,
}

const _: () = assert!(core::mem::size_of::<XattrEntry>() == 4);

#[cfg(test)]
mod tests {
    use super::*;

    // Copy a packed struct field to a local to avoid unaligned references.
    macro_rules! packed {
        ($expr:expr) => {{
            let val = $expr;
            val
        }};
    }

    // --- SuperBlock roundtrip ---

    #[test]
    fn superblock_as_bytes_from_bytes_roundtrip() {
        let sb = SuperBlock::new(5, 100, 42, 1);
        let bytes = sb.as_bytes();
        assert_eq!(bytes.len(), 128);
        let sb2 = SuperBlock::from_bytes(bytes).unwrap();
        assert_eq!(packed!(sb2.magic), EROFS_MAGIC);
        assert_eq!(packed!(sb2.root_nid), 5);
        assert_eq!(packed!(sb2.inos), 100);
        assert_eq!(packed!(sb2.blocks), 42);
        assert_eq!(packed!(sb2.meta_blkaddr), 1);
        assert_eq!(packed!(sb2.blkszbits), 12); // log2(4096)
        assert_eq!(packed!(sb2.dirblkbits), 0);
    }

    #[test]
    fn superblock_new_sets_magic_and_blkszbits() {
        let sb = SuperBlock::new(0, 1, 2, 1);
        assert_eq!(packed!(sb.magic), EROFS_MAGIC);
        assert_eq!(packed!(sb.blkszbits), BLOCK_SIZE_BITS);
        assert_eq!(packed!(sb.checksum), 0);
        assert_eq!(packed!(sb.feature_compat), 0);
        assert_eq!(packed!(sb.feature_incompat), 0);
        assert_eq!(sb.uuid, [0; 16]);
        assert_eq!(sb.volume_name, [0; 16]);
    }

    #[test]
    fn superblock_from_bytes_with_extra_data() {
        let sb = SuperBlock::new(0, 1, 2, 1);
        let mut buf = vec![0u8; 256];
        buf[..128].copy_from_slice(sb.as_bytes());
        buf[128..].fill(0xFF); // extra trailing data
        let sb2 = SuperBlock::from_bytes(&buf).unwrap();
        assert_eq!(packed!(sb2.magic), EROFS_MAGIC);
    }

    // --- InodeCompact roundtrip ---

    #[test]
    fn inode_compact_as_bytes_from_bytes_roundtrip() {
        let inode = InodeCompact::new(0o100_755, 4096, 1, 1000, 1000, EROFS_INODE_FLAT_PLAIN);
        let bytes = inode.as_bytes();
        assert_eq!(bytes.len(), 32);
        let inode2 = InodeCompact::from_bytes(bytes).unwrap();
        assert_eq!(packed!(inode2.i_mode), 0o100_755);
        assert_eq!(packed!(inode2.i_size), 4096);
        assert_eq!(packed!(inode2.i_nlink), 1);
        assert_eq!(packed!(inode2.i_uid), 1000);
        assert_eq!(packed!(inode2.i_gid), 1000);
    }

    #[test]
    fn inode_compact_data_layout_extraction() {
        // FLAT_PLAIN: layout=0, i_format = (0 << 1) | 0 = 0
        let plain = InodeCompact::new(0o100_644, 0, 1, 0, 0, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(plain.data_layout(), EROFS_INODE_FLAT_PLAIN);

        // FLAT_INLINE: layout=2, i_format = (2 << 1) | 0 = 4
        let inline = InodeCompact::new(0o100_644, 100, 1, 0, 0, EROFS_INODE_FLAT_INLINE);
        assert_eq!(inline.data_layout(), EROFS_INODE_FLAT_INLINE);
        assert_eq!(packed!(inline.i_format), 4);
    }

    #[test]
    fn inode_compact_raw_blkaddr_roundtrip() {
        let mut inode = InodeCompact::new(0o100_644, 0, 1, 0, 0, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(inode.raw_blkaddr(), 0);
        inode.set_raw_blkaddr(42);
        assert_eq!(inode.raw_blkaddr(), 42);
        inode.set_raw_blkaddr(u32::MAX);
        assert_eq!(inode.raw_blkaddr(), u32::MAX);
    }

    // --- Dirent roundtrip ---

    #[test]
    fn dirent_as_bytes_from_bytes_roundtrip() {
        let de = Dirent::new(12345, 36, EROFS_FT_REG_FILE);
        let bytes = de.as_bytes();
        assert_eq!(bytes.len(), 12);
        let de2 = Dirent::from_bytes(bytes).unwrap();
        assert_eq!(packed!(de2.nid), 12345);
        assert_eq!(packed!(de2.nameoff), 36);
        assert_eq!(packed!(de2.file_type), EROFS_FT_REG_FILE);
        assert_eq!(packed!(de2.reserved), 0);
    }

    #[test]
    fn dirent_all_file_types() {
        for &ft in &[
            EROFS_FT_REG_FILE,
            EROFS_FT_DIR,
            EROFS_FT_CHRDEV,
            EROFS_FT_BLKDEV,
            EROFS_FT_FIFO,
            EROFS_FT_SOCK,
            EROFS_FT_SYMLINK,
        ] {
            let de = Dirent::new(0, 12, ft);
            let de2 = Dirent::from_bytes(de.as_bytes()).unwrap();
            assert_eq!(packed!(de2.file_type), ft);
        }
    }

    // --- mode_to_file_type ---

    #[test]
    fn mode_to_file_type_preserves_permission_bits() {
        // Permission bits should be masked out — only S_IFMT matters
        assert_eq!(mode_to_file_type(0o100_000), EROFS_FT_REG_FILE);
        assert_eq!(mode_to_file_type(0o100_755), EROFS_FT_REG_FILE);
        assert_eq!(mode_to_file_type(0o100_644), EROFS_FT_REG_FILE);
        assert_eq!(mode_to_file_type(0o040_000), EROFS_FT_DIR);
        assert_eq!(mode_to_file_type(0o040_755), EROFS_FT_DIR);
    }

    #[test]
    fn mode_to_file_type_known_types() {
        assert_eq!(mode_to_file_type(0o010_644), EROFS_FT_FIFO);
        assert_eq!(mode_to_file_type(0o140_755), EROFS_FT_SOCK);
    }

    #[test]
    fn mode_to_file_type_unknown_returns_zero() {
        assert_eq!(mode_to_file_type(0), 0);
    }

    // --- ChunkIndex roundtrip ---

    #[test]
    fn chunk_index_as_bytes_from_bytes_roundtrip() {
        let ci = ChunkIndex::new(0, 42);
        let bytes = ci.as_bytes();
        assert_eq!(bytes.len(), 8);
        let ci2 = ChunkIndex::from_bytes(bytes).unwrap();
        assert_eq!(packed!(ci2.advise), 0);
        assert_eq!(packed!(ci2.device_id), 0);
        assert_eq!(packed!(ci2.blkaddr), 42);
    }

    #[test]
    fn chunk_index_with_device_id() {
        let ci = ChunkIndex::new(3, 100);
        let ci2 = ChunkIndex::from_bytes(ci.as_bytes()).unwrap();
        assert_eq!(packed!(ci2.device_id), 3);
        assert_eq!(packed!(ci2.blkaddr), 100);
    }

    // --- data_layout bit manipulation ---

    #[test]
    fn data_layout_encodes_in_bits_1_to_3() {
        // Verify the bit encoding: i_format = (layout << 1) | compact_flag
        // layout occupies bits 1..=3 (3-bit field)
        for layout in 0..8u16 {
            let inode = InodeCompact::new(0, 0, 0, 0, 0, layout);
            assert_eq!(
                inode.data_layout(),
                layout,
                "layout {layout} should roundtrip through i_format"
            );
        }
    }

    // --- Property-based tests ---

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// SuperBlock serialization is lossless for all field values.
            #[test]
            fn superblock_roundtrip(
                root_nid: u16, inos: u64, blocks: u32, meta_blkaddr: u32,
            ) {
                let sb = SuperBlock::new(root_nid, inos, blocks, meta_blkaddr);
                let sb2 = SuperBlock::from_bytes(sb.as_bytes()).unwrap();
                prop_assert_eq!(packed!(sb2.magic), EROFS_MAGIC);
                prop_assert_eq!(packed!(sb2.blkszbits), BLOCK_SIZE_BITS);
                prop_assert_eq!(packed!(sb2.root_nid), root_nid);
                prop_assert_eq!(packed!(sb2.inos), inos);
                prop_assert_eq!(packed!(sb2.blocks), blocks);
                prop_assert_eq!(packed!(sb2.meta_blkaddr), meta_blkaddr);
            }

            /// InodeCompact preserves all fields through as_bytes/from_bytes.
            #[test]
            fn inode_compact_roundtrip(
                mode: u16, size: u32, nlink: u16, uid: u16, gid: u16,
                layout in 0u16..8,
            ) {
                let inode = InodeCompact::new(mode, size, nlink, uid, gid, layout);
                let inode2 = InodeCompact::from_bytes(inode.as_bytes()).unwrap();
                prop_assert_eq!(packed!(inode2.i_mode), mode);
                prop_assert_eq!(packed!(inode2.i_size), size);
                prop_assert_eq!(packed!(inode2.i_nlink), nlink);
                prop_assert_eq!(packed!(inode2.i_uid), uid);
                prop_assert_eq!(packed!(inode2.i_gid), gid);
                prop_assert_eq!(inode2.data_layout(), layout);
            }

            /// InodeCompact::set_raw_blkaddr is a lossless roundtrip.
            #[test]
            fn inode_compact_blkaddr_roundtrip(addr: u32) {
                let mut inode = InodeCompact::new(0, 0, 0, 0, 0, 0);
                inode.set_raw_blkaddr(addr);
                prop_assert_eq!(inode.raw_blkaddr(), addr);
            }

            /// Dirent preserves all fields through as_bytes/from_bytes.
            #[test]
            fn dirent_roundtrip(nid: u64, nameoff: u16, file_type: u8) {
                let de = Dirent::new(nid, nameoff, file_type);
                let de2 = Dirent::from_bytes(de.as_bytes()).unwrap();
                prop_assert_eq!(packed!(de2.nid), nid);
                prop_assert_eq!(packed!(de2.nameoff), nameoff);
                prop_assert_eq!(packed!(de2.file_type), file_type);
            }

            /// mode_to_file_type depends only on S_IFMT bits (12..15), not
            /// permission bits (0..11). Two modes that differ only in permission
            /// bits must map to the same file type.
            #[test]
            fn mode_type_ignores_permissions(
                type_bits in 0u16..16, perm1: u16, perm2: u16,
            ) {
                let mode1 = (type_bits << 12) | (perm1 & 0o7777);
                let mode2 = (type_bits << 12) | (perm2 & 0o7777);
                prop_assert_eq!(
                    mode_to_file_type(mode1),
                    mode_to_file_type(mode2),
                );
            }

            /// from_bytes with truncated data returns None, never panics.
            #[test]
            fn superblock_from_short_bytes_is_none(len in 0usize..128) {
                let buf = vec![0u8; len];
                prop_assert!(SuperBlock::from_bytes(&buf).is_none());
            }

            /// from_bytes with truncated data returns None, never panics.
            #[test]
            fn inode_compact_from_short_bytes_is_none(len in 0usize..32) {
                let buf = vec![0u8; len];
                prop_assert!(InodeCompact::from_bytes(&buf).is_none());
            }

            /// from_bytes with truncated data returns None, never panics.
            #[test]
            fn dirent_from_short_bytes_is_none(len in 0usize..12) {
                let buf = vec![0u8; len];
                prop_assert!(Dirent::from_bytes(&buf).is_none());
            }

            /// ChunkIndex preserves all fields through as_bytes/from_bytes.
            #[test]
            fn chunk_index_roundtrip(device_id: u16, blkaddr: u32) {
                let ci = ChunkIndex::new(device_id, blkaddr);
                let ci2 = ChunkIndex::from_bytes(ci.as_bytes()).unwrap();
                prop_assert_eq!(packed!(ci2.advise), 0);
                prop_assert_eq!(packed!(ci2.device_id), device_id);
                prop_assert_eq!(packed!(ci2.blkaddr), blkaddr);
            }

            /// from_bytes with truncated data returns None, never panics.
            #[test]
            fn chunk_index_from_short_bytes_is_none(len in 0usize..8) {
                let buf = vec![0u8; len];
                prop_assert!(ChunkIndex::from_bytes(&buf).is_none());
            }
        }
    }
}
