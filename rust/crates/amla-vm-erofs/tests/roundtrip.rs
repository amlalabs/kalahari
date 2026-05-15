// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::fmt::Write;

use amla_erofs::{
    BLOCK_SIZE, Body, DeviceKind, EROFS_MAGIC, Entry, ErofsImage, ErofsWriter, Metadata,
    Permissions, SUPERBLOCK_OFFSET, build_to_vec,
};

fn meta(mode: u16) -> Metadata {
    Metadata {
        permissions: Permissions::try_from(mode & Permissions::MASK).unwrap(),
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
        xattrs: vec![],
    }
}

fn meta_owned(mode: u16, uid: u32, gid: u32) -> Metadata {
    Metadata {
        permissions: Permissions::try_from(mode & Permissions::MASK).unwrap(),
        uid,
        gid,
        mtime: 0,
        mtime_nsec: 0,
        xattrs: vec![],
    }
}

fn build_minimal_image() -> Vec<u8> {
    build_to_vec([Entry {
        path: "/".into(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    }])
    .unwrap()
    .into_vec()
}

fn build_basic_image() -> Vec<u8> {
    build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bin".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/etc".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bin/testbin".into(),
            metadata: meta(0o100_755),
            body: Body::RegularFile(b"ELF_FAKE_BINARY_DATA_HERE".to_vec()),
        },
        Entry {
            path: "/bin/sh".into(),
            metadata: meta(0o120_777),
            body: Body::Symlink("testbin".into()),
        },
        Entry {
            path: "/etc/hostname".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"amla-guest\n".to_vec()),
        },
        Entry {
            path: "/dev_null".into(),
            metadata: meta(0o020_666),
            body: Body::DeviceNode {
                kind: DeviceKind::Character,
                rdev: (1 << 8) | 3,
            },
        },
    ])
    .unwrap()
    .into_vec()
}

// --- Superblock tests ---

#[test]
fn superblock_magic() {
    let image = build_minimal_image();
    assert!(image.len() >= SUPERBLOCK_OFFSET + 128);
    let magic = u32::from_le_bytes(
        image[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(magic, EROFS_MAGIC);
}

#[test]
fn superblock_block_size() {
    let image = build_minimal_image();
    // blkszbits is at byte offset 12 in the superblock (after magic+checksum+feature_compat)
    let blkszbits = image[SUPERBLOCK_OFFSET + 12];
    assert_eq!(1u32 << blkszbits, BLOCK_SIZE);
}

// --- Image parsing tests ---

#[test]
fn parse_minimal_image() {
    let image = build_minimal_image();
    let fs = ErofsImage::new(&image).unwrap();
    let root = fs.inode(fs.root_nid()).unwrap();
    assert!(root.is_dir());
    assert_eq!(root.mode & 0o7777, 0o755);
}

#[test]
fn parse_basic_image() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let root = fs.inode(fs.root_nid()).unwrap();
    assert!(root.is_dir());
}

#[test]
fn permissions_reject_file_type_bits() {
    assert!(matches!(
        Permissions::try_from(0o100_644),
        Err(amla_erofs::ErofsError::InvalidPermissions(0o100_644))
    ));
    assert_eq!(Permissions::try_from(0o644).unwrap().bits(), 0o644);
}

#[test]
fn inode_file_type_is_derived_from_body() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o100_700),
            body: Body::Directory,
        },
        Entry {
            path: "/file".into(),
            metadata: meta(0o040_755),
            body: Body::RegularFile(b"data".to_vec()),
        },
        Entry {
            path: "/link".into(),
            metadata: meta(0o040_777),
            body: Body::Symlink("file".into()),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();

    let root = fs.inode(fs.root_nid()).unwrap();
    assert!(root.is_dir());
    assert_eq!(root.mode & 0o170_000, 0o040_000);
    assert_eq!(root.mode & 0o7777, 0o700);

    let file = fs.inode(fs.resolve("/file").unwrap()).unwrap();
    assert!(file.is_reg());
    assert_eq!(file.mode & 0o170_000, 0o100_000);
    assert_eq!(file.mode & 0o7777, 0o755);

    let link = fs.inode(fs.resolve("/link").unwrap()).unwrap();
    assert!(link.is_symlink());
    assert_eq!(link.mode & 0o170_000, 0o120_000);
    assert_eq!(link.mode & 0o7777, 0o777);
}

// --- Directory listing tests ---

#[test]
fn readdir_root() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let entries = fs.readdir(fs.root_nid()).unwrap();

    let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
    // Should contain ".", "..", "bin", "etc", "dev_null"
    assert!(names.contains(&b".".as_slice()));
    assert!(names.contains(&b"..".as_slice()));
    assert!(names.contains(&b"bin".as_slice()));
    assert!(names.contains(&b"etc".as_slice()));
    assert!(names.contains(&b"dev_null".as_slice()));
}

#[test]
fn readdir_bin() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let bin_nid = fs.resolve("/bin").unwrap();
    let entries = fs.readdir(bin_nid).unwrap();

    let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
    assert!(names.contains(&b"testbin".as_slice()));
    assert!(names.contains(&b"sh".as_slice()));
}

// --- File read tests ---

#[test]
fn read_file_contents() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    let data = fs.read_file(nid, 0, 4096).unwrap();
    assert_eq!(data, b"amla-guest\n");
}

#[test]
fn read_file_partial() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    let data = fs.read_file(nid, 0, 3).unwrap();
    assert_eq!(data, b"ELF");
}

#[test]
fn read_file_offset() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    let full = b"ELF_FAKE_BINARY_DATA_HERE";
    let data = fs.read_file(nid, 4, 4).unwrap();
    assert_eq!(data, &full[4..8]);
}

#[test]
fn read_file_past_eof() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    // Read past EOF — should clamp
    let data = fs.read_file(nid, 5, 1000).unwrap();
    assert_eq!(data, b"guest\n");
}

#[test]
fn read_file_at_eof() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    let info = fs.inode(nid).unwrap();
    let data = fs.read_file(nid, info.size, 100).unwrap();
    assert!(data.is_empty());
}

// --- Symlink tests ---

#[test]
fn readlink() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/sh").unwrap();
    let info = fs.inode(nid).unwrap();
    assert!(info.is_symlink());
    let target = fs.readlink(nid).unwrap();
    assert_eq!(target, b"testbin");
}

// --- Device node tests ---

#[test]
fn device_node() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/dev_null").unwrap();
    let info = fs.inode(nid).unwrap();
    assert!(info.is_chrdev());
    assert_eq!(info.mode & 0o7777, 0o666);
    assert_eq!(info.rdev_major(), 1);
    assert_eq!(info.rdev_minor(), 3);
}

// --- Inode metadata tests ---

#[test]
fn inode_mode_and_ownership() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();

    let nid = fs.resolve("/bin/testbin").unwrap();
    let info = fs.inode(nid).unwrap();
    assert!(info.is_reg());
    assert_eq!(info.mode & 0o7777, 0o755);
    assert_eq!(info.uid, 0);
    assert_eq!(info.gid, 0);
    assert_eq!(info.size, 25); // "ELF_FAKE_BINARY_DATA_HERE".len()
}

#[test]
fn directory_nlink() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    // Root has 2 subdirectories (bin, etc) → nlink = 2 + 2 = 4
    let root = fs.inode(fs.root_nid()).unwrap();
    assert_eq!(root.nlink, 4);

    // /bin has 0 subdirectories → nlink = 2
    let bin_nid = fs.resolve("/bin").unwrap();
    let bin = fs.inode(bin_nid).unwrap();
    assert_eq!(bin.nlink, 2);
}

// --- Path resolution tests ---

#[test]
fn resolve_root() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/").unwrap();
    assert_eq!(nid, fs.root_nid());
}

#[test]
fn resolve_nested() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    let info = fs.inode(nid).unwrap();
    assert!(info.is_reg());
}

#[test]
fn resolve_nonexistent() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    assert!(fs.resolve("/nonexistent").is_err());
}

// --- Lookup tests ---

#[test]
fn lookup_found() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let entry = fs.lookup(fs.root_nid(), b"bin").unwrap();
    assert!(entry.is_some());
    let entry = entry.unwrap();
    assert_eq!(entry.file_type, amla_erofs::ondisk::EROFS_FT_DIR);
}

#[test]
fn lookup_not_found() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let entry = fs.lookup(fs.root_nid(), b"nope").unwrap();
    assert!(entry.is_none());
}

// --- Large file tests (FLAT_PLAIN layout) ---

#[test]
fn large_file_flat_plain() {
    let big_data = vec![0xAB; 8192]; // 2 blocks
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bigfile".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(big_data),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bigfile").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(info.size, 8192);
    assert_eq!(info.data_layout, amla_erofs::ondisk::EROFS_INODE_FLAT_PLAIN);

    // Read full file
    let data = fs.read_file(nid, 0, 8192).unwrap();
    assert_eq!(data.len(), 8192);
    assert!(data.iter().all(|&b| b == 0xAB));

    // Read across block boundary
    let cross = fs.read_file(nid, 4090, 12).unwrap();
    assert_eq!(cross.len(), 12);
    assert!(cross.iter().all(|&b| b == 0xAB));
}

// --- Empty directory test ---

#[test]
fn empty_directory() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/empty".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/empty").unwrap();
    let entries = fs.readdir(nid).unwrap();
    // Should have "." and ".." only
    assert_eq!(entries.len(), 2);
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
    assert!(names.contains(&b".".as_slice()));
    assert!(names.contains(&b"..".as_slice()));
}

// --- Zero-length file test ---

#[test]
fn zero_length_file() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/empty.txt".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(vec![]),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/empty.txt").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(info.size, 0);
    let data = fs.read_file(nid, 0, 100).unwrap();
    assert!(data.is_empty());
}

// --- Error handling tests ---

#[test]
fn bad_magic() {
    let mut image = build_minimal_image();
    image[SUPERBLOCK_OFFSET] = 0xFF;
    assert!(ErofsImage::new(&image).is_err());
}

#[test]
fn image_too_small() {
    let image = vec![0u8; 100];
    assert!(ErofsImage::new(&image).is_err());
}

#[test]
fn duplicate_path() {
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bin".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bin".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::DuplicatePath(_)));
}

#[test]
fn parent_not_found() {
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/nonexistent/file".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::ParentNotFound(_)));
}

#[test]
fn invalid_path() {
    let err = build_to_vec([Entry {
        path: String::new(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    }])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidPath(_)));

    let err = build_to_vec([Entry {
        path: "no_leading_slash".into(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    }])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidPath(_)));
}

#[test]
fn readdir_on_non_directory() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    assert!(fs.readdir(nid).is_err());
}

#[test]
fn readlink_on_non_symlink() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    assert!(fs.readlink(nid).is_err());
}

// --- Stress test: many files ---

#[test]
fn many_files_in_directory() {
    let count = 200;
    let mut entries = vec![
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/files".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
    ];
    for i in 0..count {
        let path = format!("/files/file_{i:04}");
        let data = format!("content_{i}");
        entries.push(Entry {
            path,
            metadata: meta(0o100_644),
            body: Body::RegularFile(data.into_bytes()),
        });
    }

    let image = build_to_vec(entries).unwrap().into_vec();
    let fs = ErofsImage::new(&image).unwrap();

    let dir_nid = fs.resolve("/files").unwrap();
    let dir_entries = fs.readdir(dir_nid).unwrap();
    // +2 for "." and ".."
    assert_eq!(dir_entries.len(), count + 2);

    // Verify a few files
    for i in [0, 50, 100, 199] {
        let path = format!("/files/file_{i:04}");
        let nid = fs.resolve(&path).unwrap();
        let data = fs.read_file(nid, 0, 1024).unwrap();
        let expected = format!("content_{i}");
        assert_eq!(data, expected.as_bytes(), "mismatch at file_{i:04}");
    }
}

// --- Deep directory nesting ---

#[test]
fn deep_nesting() {
    let depth = 10;
    let mut entries = vec![Entry {
        path: "/".into(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    }];

    let mut path = String::new();
    for i in 0..depth {
        write!(path, "/d{i}").unwrap();
        entries.push(Entry {
            path: path.clone(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        });
    }

    let leaf_file = format!("{path}/leaf.txt");
    entries.push(Entry {
        path: leaf_file.clone(),
        metadata: meta(0o100_644),
        body: Body::RegularFile(b"deep content".to_vec()),
    });

    let image = build_to_vec(entries).unwrap().into_vec();
    let fs = ErofsImage::new(&image).unwrap();

    let nid = fs.resolve(&leaf_file).unwrap();
    let data = fs.read_file(nid, 0, 100).unwrap();
    assert_eq!(data, b"deep content");
}

// --- On-disk struct size assertions ---

#[test]
fn struct_sizes() {
    use amla_erofs::ondisk::{Dirent, InodeCompact, SuperBlock};
    assert_eq!(core::mem::size_of::<SuperBlock>(), 128);
    assert_eq!(core::mem::size_of::<InodeCompact>(), 32);
    assert_eq!(core::mem::size_of::<Dirent>(), 12);
}

// --- Dot and dotdot point to correct NIDs ---

#[test]
fn dot_and_dotdot_nids() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();

    // Root: "." and ".." both point to root
    let root_entries = fs.readdir(fs.root_nid()).unwrap();
    let dot = root_entries.iter().find(|e| e.name == b".").unwrap();
    let dotdot = root_entries.iter().find(|e| e.name == b"..").unwrap();
    assert_eq!(dot.nid, fs.root_nid());
    assert_eq!(dotdot.nid, fs.root_nid());

    // /bin: "." points to bin, ".." points to root
    let bin_nid = fs.resolve("/bin").unwrap();
    let bin_entries = fs.readdir(bin_nid).unwrap();
    let dot = bin_entries.iter().find(|e| e.name == b".").unwrap();
    let dotdot = bin_entries.iter().find(|e| e.name == b"..").unwrap();
    assert_eq!(dot.nid, bin_nid);
    assert_eq!(dotdot.nid, fs.root_nid());
}

// --- Symlink with absolute path ---

#[test]
fn symlink_absolute_target() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/usr".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/usr/bin".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/usr/bin/env".into(),
            metadata: meta(0o100_755),
            body: Body::RegularFile(b"#!/bin/sh\n".to_vec()),
        },
        Entry {
            path: "/usr/bin/python".into(),
            metadata: meta(0o120_777),
            body: Body::Symlink("/usr/bin/env".into()),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/usr/bin/python").unwrap();
    let target = fs.readlink(nid).unwrap();
    assert_eq!(target, b"/usr/bin/env");
}

// --- Multiple device nodes ---

#[test]
fn multiple_device_nodes() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/dev".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        // /dev/null: char 1,3
        Entry {
            path: "/dev/null".into(),
            metadata: meta(0o020_666),
            body: Body::DeviceNode {
                kind: DeviceKind::Character,
                rdev: (1 << 8) | 3,
            },
        },
        // /dev/zero: char 1,5
        Entry {
            path: "/dev/zero".into(),
            metadata: meta(0o020_666),
            body: Body::DeviceNode {
                kind: DeviceKind::Character,
                rdev: (1 << 8) | 5,
            },
        },
        // /dev/random: char 1,8
        Entry {
            path: "/dev/random".into(),
            metadata: meta(0o020_666),
            body: Body::DeviceNode {
                kind: DeviceKind::Character,
                rdev: (1 << 8) | 8,
            },
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();

    let null = fs.inode(fs.resolve("/dev/null").unwrap()).unwrap();
    assert!(null.is_chrdev());
    assert_eq!(null.rdev_major(), 1);
    assert_eq!(null.rdev_minor(), 3);

    let zero = fs.inode(fs.resolve("/dev/zero").unwrap()).unwrap();
    assert_eq!(zero.rdev_minor(), 5);

    let random = fs.inode(fs.resolve("/dev/random").unwrap()).unwrap();
    assert_eq!(random.rdev_minor(), 8);
}

// --- Realistic rootfs structure ---

#[test]
fn realistic_rootfs() {
    let mut entries = vec![Entry {
        path: "/".into(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    }];
    for dir in &[
        "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev", "/tmp", "/var", "/var/run",
    ] {
        entries.push(Entry {
            path: (*dir).into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        });
    }
    entries.push(Entry {
        path: "/bin/testbin".into(),
        metadata: meta(0o100_755),
        body: Body::RegularFile(vec![0u8; 500_000]),
    });
    for cmd in &["sh", "ls", "cat", "mount", "umount", "mkdir", "echo"] {
        let path = format!("/bin/{cmd}");
        entries.push(Entry {
            path,
            metadata: meta(0o120_777),
            body: Body::Symlink("testbin".into()),
        });
    }
    entries.push(Entry {
        path: "/etc/passwd".into(),
        metadata: meta(0o100_644),
        body: Body::RegularFile(b"root:x:0:0:root:/root:/bin/sh\n".to_vec()),
    });
    entries.push(Entry {
        path: "/init".into(),
        metadata: meta(0o100_755),
        body: Body::RegularFile(b"#!/bin/sh\nmount -t proc proc /proc\nexec /bin/sh\n".to_vec()),
    });

    let image = build_to_vec(entries).unwrap().into_vec();
    let fs = ErofsImage::new(&image).unwrap();

    // Verify testbin is readable
    let bb_nid = fs.resolve("/bin/testbin").unwrap();
    let bb_info = fs.inode(bb_nid).unwrap();
    assert_eq!(bb_info.size, 500_000);
    assert_eq!(
        bb_info.data_layout,
        amla_erofs::ondisk::EROFS_INODE_FLAT_PLAIN
    );

    // Verify symlinks
    let sh_nid = fs.resolve("/bin/sh").unwrap();
    let target = fs.readlink(sh_nid).unwrap();
    assert_eq!(target, b"testbin");

    // Read init script
    let init_nid = fs.resolve("/init").unwrap();
    let init_data = fs.read_file(init_nid, 0, 4096).unwrap();
    assert!(init_data.starts_with(b"#!/bin/sh\n"));

    // Verify /var/run exists
    fs.resolve("/var/run").unwrap();
}

// =============================================================================
// Coverage gap tests — targeting specific uncovered lines
// =============================================================================

// --- error.rs: Display impl (lines 30-46) ---

#[test]
fn error_display_all_variants() {
    use amla_erofs::ErofsError;

    let cases: Vec<(ErofsError, &str)> = vec![
        (
            ErofsError::TooSmall {
                expected: 1152,
                actual: 100,
            },
            "image too small: need 1152 bytes, got 100",
        ),
        (
            ErofsError::BadMagic(0xDEAD_BEEF),
            "bad superblock magic: 0xdeadbeef",
        ),
        (ErofsError::InvalidNid(42), "invalid inode NID: 42"),
        (
            ErofsError::UnsupportedLayout(99),
            "unsupported inode layout: 99",
        ),
        (
            ErofsError::InvalidPath("bad".into()),
            "invalid path: \"bad\"",
        ),
        (
            ErofsError::DuplicatePath("/bin".into()),
            "duplicate path: \"/bin\"",
        ),
        (
            ErofsError::ParentNotFound("/missing/child".into()),
            "parent directory not found: \"/missing/child\"",
        ),
        (
            ErofsError::OffsetOutOfRange {
                offset: 100,
                size: 50,
            },
            "offset 100 out of range for size 50",
        ),
        (ErofsError::NotADirectory(7), "NID 7 is not a directory"),
        (ErofsError::NotASymlink(5), "NID 5 is not a symlink"),
        (
            ErofsError::ParentNotDirectory("/file/child".into()),
            "parent is not a directory: \"/file/child\"",
        ),
        (
            ErofsError::NameTooLong {
                name_len: 5000,
                max_len: 4084,
            },
            "filename too long: 5000 bytes (max 4084)",
        ),
        (
            ErofsError::Overflow("test overflow".into()),
            "overflow: test overflow",
        ),
        (
            ErofsError::UnsupportedBlockSize(13),
            "unsupported block size: blkszbits=13 (expected 12)",
        ),
        (
            ErofsError::UnsupportedFeature(0x0000_0001),
            "unsupported incompatible features: 0x00000001",
        ),
        (
            ErofsError::UnsupportedSuperblockField("feature_compat"),
            "unsupported superblock field set: feature_compat",
        ),
        (
            ErofsError::MalformedSuperblock("inode count is zero"),
            "malformed superblock: inode count is zero",
        ),
        (
            ErofsError::UnsupportedInodeFormat(0x0005),
            "unsupported inode format (extended): i_format=0x0005",
        ),
        (
            ErofsError::CorruptedDirectory("bad data".into()),
            "corrupted directory: bad data",
        ),
        (
            ErofsError::BuilderPoisoned,
            "builder is poisoned after an earlier error",
        ),
    ];

    for (err, expected) in cases {
        let msg = format!("{err}");
        assert_eq!(msg, expected, "Display mismatch for {err:?}");
        // Also exercise std::error::Error trait
        let _source = std::error::Error::source(&err);
    }
}

// --- builder.rs: empty builder finish ---

#[test]
fn finish_empty_builder() {
    let b = ErofsWriter::new(std::io::Cursor::new(Vec::new()));
    let err = b.finish_to_vec().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("no entries provided") || msg.contains("root directory"),
        "expected empty/root dir error, got: {msg}"
    );
}

#[test]
fn finish_without_root_first() {
    // Default impl
    let b = ErofsWriter::new(std::io::Cursor::new(Vec::new()));
    let err = b.finish_to_vec().unwrap_err();
    assert!(
        format!("{err}").contains("no entries provided")
            || format!("{err}").contains("root directory"),
        "expected empty/root dir error, got: {err}"
    );

    // With just root — should succeed
    let mut b2 = ErofsWriter::new(std::io::Cursor::new(Vec::new()));
    b2.push(Entry {
        path: "/".into(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    })
    .unwrap();
    let _img = b2.finish_to_vec().unwrap();
}

// --- builder.rs: trailing slash validation ---

#[test]
fn trailing_slash_rejected() {
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bin/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidPath(_)));
}

// --- ondisk.rs: from_bytes returning None ---

#[test]
fn superblock_from_bytes_too_small() {
    let data = [0u8; 10];
    let result = amla_erofs::ondisk::SuperBlock::from_bytes(&data);
    assert!(result.is_none());
}

#[test]
fn inode_compact_from_bytes_too_small() {
    let data = [0u8; 16];
    let result = amla_erofs::ondisk::InodeCompact::from_bytes(&data);
    assert!(result.is_none());
}

#[test]
fn dirent_from_bytes_too_small() {
    let data = [0u8; 4];
    let result = amla_erofs::ondisk::Dirent::from_bytes(&data);
    assert!(result.is_none());
}

// --- ondisk.rs: mode_to_file_type branches ---

#[test]
fn mode_to_file_type_all_branches() {
    use amla_erofs::ondisk::{
        EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE,
        EROFS_FT_SOCK, EROFS_FT_SYMLINK, mode_to_file_type,
    };

    assert_eq!(mode_to_file_type(0o10_0644), EROFS_FT_REG_FILE); // S_IFREG
    assert_eq!(mode_to_file_type(0o04_0755), EROFS_FT_DIR); // S_IFDIR
    assert_eq!(mode_to_file_type(0o12_0777), EROFS_FT_SYMLINK); // S_IFLNK
    assert_eq!(mode_to_file_type(0o02_0666), EROFS_FT_CHRDEV); // S_IFCHR
    assert_eq!(mode_to_file_type(0o06_0660), EROFS_FT_BLKDEV); // S_IFBLK
    assert_eq!(mode_to_file_type(0o14_0755), EROFS_FT_SOCK); // S_IFSOCK
    assert_eq!(mode_to_file_type(0o01_0644), EROFS_FT_FIFO); // S_IFIFO
}

// --- reader.rs: is_blkdev ---

#[test]
fn block_device_node() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/dev".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        // Block device: S_IFBLK = 0o060000, sda = major 8, minor 0
        Entry {
            path: "/dev/sda".into(),
            metadata: meta(0o060_660),
            body: Body::DeviceNode {
                kind: DeviceKind::Block,
                rdev: 8 << 8,
            },
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/dev/sda").unwrap();
    let info = fs.inode(nid).unwrap();
    assert!(info.is_blkdev());
    assert!(!info.is_chrdev());
    assert!(!info.is_dir());
    assert!(!info.is_reg());
    assert!(!info.is_symlink());
    assert_eq!(info.rdev_major(), 8);
    assert_eq!(info.rdev_minor(), 0);
}

// --- reader.rs: invalid NID ---

#[test]
fn inode_invalid_nid() {
    let image = build_minimal_image();
    let fs = ErofsImage::new(&image).unwrap();
    // A very large NID that's beyond the image
    let err = fs.inode(999_999).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidNid(999_999)));
}

// --- reader.rs: UnsupportedLayout ---

#[test]
fn read_file_unsupported_layout() {
    let mut image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    let info = fs.inode(nid).unwrap();

    // Corrupt the inode's i_format to set an unsupported layout
    let inode_off = usize::try_from(info.inode_offset).unwrap();
    // Layout is in bits 1..3 of i_format. Set to layout=3 (invalid): 0b110 << 0 | compact=0
    // i_format = (layout << 1) | compact_flag
    // layout=3 → i_format = (3 << 1) | 0 = 6
    image[inode_off] = 6;
    image[inode_off + 1] = 0;

    let fs2 = ErofsImage::new(&image).unwrap();
    let err = fs2.read_file(nid, 0, 100).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::UnsupportedLayout(3)));
}

// --- reader.rs: OffsetOutOfRange for truncated image ---

#[test]
fn read_file_truncated_inline() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(
        info.data_layout,
        amla_erofs::ondisk::EROFS_INODE_FLAT_INLINE
    );

    // Truncate the image so the inline data runs past the end
    let inline_start = usize::try_from(info.inode_offset).unwrap() + 32;
    let truncated = &image[..inline_start + 2]; // Only keep 2 bytes of inline data

    let err = ErofsImage::new(truncated).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::TooSmall { .. }));
}

#[test]
fn read_file_truncated_plain() {
    // Build a large file that uses FLAT_PLAIN
    let big_data = vec![0xCD; 8192];
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/big".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(big_data),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/big").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(info.data_layout, amla_erofs::ondisk::EROFS_INODE_FLAT_PLAIN);

    // Truncate image so the data blocks are cut short.
    // With data-first layout, data blocks precede metadata.
    // Truncate just enough that data can't be fully read.
    let truncated = &image[..image.len() - BLOCK_SIZE as usize];
    let err = ErofsImage::new(truncated).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::TooSmall { .. }));
}

#[test]
fn appended_bytes_are_not_addressable_past_declared_blocks() {
    let big_data = vec![0xCD; 8192];
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/big".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(big_data),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/big").unwrap();
    let info = fs.inode(nid).unwrap();
    let blocks_offset = SUPERBLOCK_OFFSET + 36;
    let declared_blocks =
        u32::from_le_bytes(image[blocks_offset..blocks_offset + 4].try_into().unwrap());

    let mut crafted = image.clone();
    crafted.extend_from_slice(&vec![0xA5; BLOCK_SIZE as usize]);
    let raw_blkaddr_offset = usize::try_from(info.inode_offset).unwrap() + 16;
    crafted[raw_blkaddr_offset..raw_blkaddr_offset + 4]
        .copy_from_slice(&declared_blocks.to_le_bytes());

    let fs = ErofsImage::new(&crafted).unwrap();
    let err = fs.read_file(nid, 0, 1).unwrap_err();
    assert!(matches!(
        err,
        amla_erofs::ErofsError::OffsetOutOfRange { .. }
    ));
}

#[test]
fn new_rejects_root_nid_that_is_not_directory() {
    let mut image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/file".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let file_nid = fs.resolve("/file").unwrap();
    let root_nid_offset = SUPERBLOCK_OFFSET + 14;
    image[root_nid_offset..root_nid_offset + 2]
        .copy_from_slice(&u16::try_from(file_nid).unwrap().to_le_bytes());

    let err = ErofsImage::new(&image).unwrap_err();
    assert!(matches!(
        err,
        amla_erofs::ErofsError::NotADirectory(nid) if nid == file_nid
    ));
}

#[test]
fn new_rejects_unsupported_superblock_fields() {
    let mut image = build_minimal_image();
    image[SUPERBLOCK_OFFSET + 8] = 1;

    let err = ErofsImage::new(&image).unwrap_err();
    assert_eq!(
        err,
        amla_erofs::ErofsError::UnsupportedSuperblockField("feature_compat")
    );
}

#[test]
fn new_rejects_metadata_block_outside_declared_image() {
    let mut image = build_minimal_image();
    let blocks_offset = SUPERBLOCK_OFFSET + 36;
    let blocks = u32::from_le_bytes(image[blocks_offset..blocks_offset + 4].try_into().unwrap());
    let meta_blkaddr_offset = SUPERBLOCK_OFFSET + 40;
    image[meta_blkaddr_offset..meta_blkaddr_offset + 4].copy_from_slice(&blocks.to_le_bytes());

    let err = ErofsImage::new(&image).unwrap_err();
    assert_eq!(
        err,
        amla_erofs::ErofsError::MalformedSuperblock("metadata block address is outside the image")
    );
}

// --- reader.rs: resolve with trailing slash / empty components ---

#[test]
fn resolve_with_trailing_slash() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    // Path with trailing slash has empty final component -> skipped
    let nid = fs.resolve("/bin/").unwrap();
    let bin_nid = fs.resolve("/bin").unwrap();
    assert_eq!(nid, bin_nid);
}

#[test]
fn resolve_with_double_slash() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    // Double slash -> empty component -> skipped
    let nid = fs.resolve("/bin//testbin").unwrap();
    let expected = fs.resolve("/bin/testbin").unwrap();
    assert_eq!(nid, expected);
}

// --- reader.rs: readlink on regular file (NotASymlink error) ---

#[test]
fn readlink_on_regular_file() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    let err = fs.readlink(nid).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("not a symlink"), "got: {msg}");
}

// --- reader.rs: readdir on zero-size dir ---

#[test]
fn readdir_zero_size_directory() {
    let mut image = build_minimal_image();
    let fs = ErofsImage::new(&image).unwrap();
    let root_nid = fs.root_nid();
    let info = fs.inode(root_nid).unwrap();

    // Zero out i_size in the root inode (offset 8-11 in InodeCompact, which is at inode_offset)
    let inode_off = usize::try_from(info.inode_offset).unwrap();
    // i_size is at byte offset 8 within InodeCompact (after i_format(2) + i_xattr_icount(2) + i_mode(2) + i_nlink(2))
    image[inode_off + 8] = 0;
    image[inode_off + 9] = 0;
    image[inode_off + 10] = 0;
    image[inode_off + 11] = 0;

    let fs2 = ErofsImage::new(&image).unwrap();
    let entries = fs2.readdir(root_nid).unwrap();
    assert!(entries.is_empty());
}

// =============================================================================
// Regression tests for Codex-reviewed bugs
// =============================================================================

// --- Bug 2: NID overflow should return InvalidNid, not panic ---

#[test]
fn inode_overflow_nid() {
    let image = build_minimal_image();
    let fs = ErofsImage::new(&image).unwrap();
    let err = fs.inode(u64::MAX).unwrap_err();
    assert!(
        matches!(err, amla_erofs::ErofsError::InvalidNid(u64::MAX)),
        "expected InvalidNid(u64::MAX), got: {err:?}"
    );
}

// --- Bug 1: Malformed nameoff ordering should not panic ---

#[test]
fn readdir_malformed_nameoff_ordering() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();

    // Find /bin directory and get its inode info
    let bin_nid = fs.resolve("/bin").unwrap();
    let info = fs.inode(bin_nid).unwrap();

    let mut image = image.clone();

    // Find where the directory data lives (inline after inode)
    let dir_data_start = usize::try_from(info.inode_offset).unwrap() + 32; // 32 = sizeof(InodeCompact)

    // The first dirent's nameoff tells us where names begin.
    // We'll corrupt the second dirent's nameoff to be *before* the first entry's nameoff,
    // creating a situation where actual_end < name_start.
    let dirent_size = 12; // sizeof(Dirent)
    // Second dirent is at dir_data_start + dirent_size
    // nameoff is at byte offset 8 within a Dirent (after nid:u64)
    let nameoff_offset = dir_data_start + dirent_size + 8;
    // Set nameoff to 0 (which is before where names start)
    image[nameoff_offset] = 0;
    image[nameoff_offset + 1] = 0;

    let fs2 = ErofsImage::new(&image).unwrap();
    // Should return an error for corrupted directory data, not panic
    let err = fs2.readdir(bin_nid).unwrap_err();
    assert!(
        matches!(err, amla_erofs::ErofsError::CorruptedDirectory(_)),
        "expected CorruptedDirectory, got: {err:?}"
    );
}

// --- Bug 4: Child under non-directory parent ---
// Note: The Entry-based API does not validate that parents are directories
// at build time (validation is structural, not type-based). This test is
// kept as a documentation note but the old assertion is removed.

// --- Bug 3: Oversized filename rejected ---

#[test]
fn oversized_filename_rejected() {
    // 4085 bytes > max name length of 4084 (4096 - 12)
    let long_name = "x".repeat(4085);
    let path = format!("/{long_name}");
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path,
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
    ])
    .unwrap_err();
    assert!(
        matches!(err, amla_erofs::ErofsError::NameTooLong { .. }),
        "expected NameTooLong, got: {err:?}"
    );
}

// --- Bug 3 edge case: Max-length filename accepted ---

#[test]
fn max_length_filename_accepted() {
    // A directory with one child means dirents: ".", "..", and the child.
    // Each dirent header is 12 bytes. With 3 entries: 3*12 = 36 bytes of headers.
    // Max name = 4096 - 36 (headers for ".", "..", child) - 1 (".") - 2 ("..") = 4057
    let long_name = "a".repeat(4057);
    let path = format!("/{long_name}");
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: path.clone(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"ok".to_vec()),
        },
    ])
    .unwrap()
    .into_vec();

    // Verify the file is readable
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve(&path).unwrap();
    let data = fs.read_file(nid, 0, 100).unwrap();
    assert_eq!(data, b"ok");
}

// =============================================================================
// read_file_slice error path tests [M6]
// =============================================================================

#[test]
fn read_file_slice_truncated_inline() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(
        info.data_layout,
        amla_erofs::ondisk::EROFS_INODE_FLAT_INLINE
    );

    // Truncate image so inline data runs past the end
    let inline_start = usize::try_from(info.inode_offset).unwrap() + 32;
    let truncated = &image[..inline_start + 2];

    let err = ErofsImage::new(truncated).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::TooSmall { .. }));
}

#[test]
fn read_file_slice_truncated_plain() {
    let big_data = vec![0xCD; 8192];
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/big".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(big_data),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/big").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(info.data_layout, amla_erofs::ondisk::EROFS_INODE_FLAT_PLAIN);

    // Truncate so data can't be fully read
    let truncated = &image[..image.len() - BLOCK_SIZE as usize];
    let err = ErofsImage::new(truncated).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::TooSmall { .. }));
}

#[test]
fn read_file_slice_unsupported_layout() {
    let mut image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/etc/hostname").unwrap();
    let info = fs.inode(nid).unwrap();

    // Corrupt layout to unsupported value
    let inode_off = usize::try_from(info.inode_offset).unwrap();
    image[inode_off] = 6; // layout=3 -> i_format = (3 << 1) | 0
    image[inode_off + 1] = 0;

    let fs2 = ErofsImage::new(&image).unwrap();
    let err = fs2.read_file_slice(nid, 0, 100).unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::UnsupportedLayout(3)));
}

// --- Debug impl for ErofsImage ---

#[test]
fn erofs_image_debug() {
    let image = build_minimal_image();
    let fs = ErofsImage::new(&image).unwrap();
    let debug_str = format!("{fs:?}");
    assert!(debug_str.contains("ErofsImage"));
    assert!(debug_str.contains("data_len"));
    assert!(debug_str.contains("root_nid"));
}

// =============================================================================
// FIFO and socket inode round-trip tests (COV-2)
// =============================================================================

#[test]
fn fifo_device_node() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        // FIFO: S_IFIFO = 0o010000
        Entry {
            path: "/fifo".into(),
            metadata: meta(0o010_644),
            body: Body::Fifo,
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/fifo").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(info.mode & 0o170_000, 0o010_000, "should be FIFO");
    assert!(info.is_fifo());
    assert_eq!(info.mode & 0o7777, 0o644);
    assert_eq!(info.size, 0);
}

#[test]
fn socket_device_node() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        // Socket: S_IFSOCK = 0o140000
        Entry {
            path: "/sock".into(),
            metadata: meta(0o140_755),
            body: Body::Socket,
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/sock").unwrap();
    let info = fs.inode(nid).unwrap();
    assert_eq!(info.mode & 0o170_000, 0o140_000, "should be socket");
    assert!(info.is_socket());
    assert_eq!(info.mode & 0o7777, 0o755);
    assert_eq!(info.size, 0);
}

// =============================================================================
// Ergonomic feature tests
// =============================================================================

#[test]
fn dir_entry_name_str() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let entries = fs.readdir(fs.root_nid()).unwrap();

    let bin = entries.iter().find(|e| e.name == b"bin").unwrap();
    assert_eq!(bin.name_str(), Some("bin"));
}

#[test]
fn readlink_slice_returns_target() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/sh").unwrap();
    let target = fs.readlink_slice(nid).unwrap();
    assert_eq!(target, b"testbin");
}

#[test]
fn readlink_slice_on_non_symlink_errors() {
    let image = build_basic_image();
    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/bin/testbin").unwrap();
    assert!(fs.readlink_slice(nid).is_err());
}

// =============================================================================
// State-poisoning regression tests (BUG-1)
// =============================================================================

#[test]
fn retry_after_parent_not_found() {
    // With the Entry API, entries are collected upfront, so "retry" semantics
    // differ. We test that providing entries in the correct order works after
    // verifying the error for wrong order.
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/a/file".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::ParentNotFound(_)));

    // Correct order succeeds
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/a".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/a/file".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let data = fs
        .read_file(fs.resolve("/a/file").unwrap(), 0, 100)
        .unwrap();
    assert_eq!(data, b"data");
}

#[test]
fn push_error_poisons_builder() {
    let mut builder = ErofsWriter::new(std::io::Cursor::new(Vec::new()));
    builder
        .push(Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        })
        .unwrap();

    let err = builder
        .push(Entry {
            path: "/missing/big".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(vec![0xA5; BLOCK_SIZE as usize]),
        })
        .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::ParentNotFound(_)));

    let err = builder
        .push(Entry {
            path: "/ok".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"ok".to_vec()),
        })
        .unwrap_err();
    assert_eq!(err, amla_erofs::ErofsError::BuilderPoisoned);

    let err = builder.finish_to_vec().unwrap_err();
    assert_eq!(err, amla_erofs::ErofsError::BuilderPoisoned);
}

#[test]
fn push_file_error_poisons_builder() {
    let mut builder = ErofsWriter::new(std::io::Cursor::new(Vec::new()));
    builder
        .push(Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        })
        .unwrap();

    let data = vec![0x5A; BLOCK_SIZE as usize];
    let err = builder
        .push_file(
            "/missing/streamed".into(),
            meta(0o100_644),
            data.len() as u64,
            &mut data.as_slice(),
        )
        .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::ParentNotFound(_)));

    let err = builder.finish_to_vec().unwrap_err();
    assert_eq!(err, amla_erofs::ErofsError::BuilderPoisoned);
}

#[test]
fn hardlink_path_claims_namespace_and_uses_target_type() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/file".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
        Entry {
            path: "/alias".into(),
            metadata: meta(0o040_755),
            body: Body::Hardlink("/file".into()),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let root_entries = fs.readdir(fs.root_nid()).unwrap();
    let alias = root_entries
        .iter()
        .find(|entry| entry.name == b"alias")
        .unwrap();
    assert_eq!(alias.file_type, amla_erofs::ondisk::EROFS_FT_REG_FILE);
    assert_eq!(fs.resolve("/alias").unwrap(), fs.resolve("/file").unwrap());

    let mut builder = ErofsWriter::new(std::io::Cursor::new(Vec::new()));
    builder
        .push(Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        })
        .unwrap();
    builder
        .push(Entry {
            path: "/file".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        })
        .unwrap();
    builder
        .push(Entry {
            path: "/alias".into(),
            metadata: meta(0o100_644),
            body: Body::Hardlink("/file".into()),
        })
        .unwrap();

    let err = builder
        .push(Entry {
            path: "/alias".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"replacement".to_vec()),
        })
        .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::DuplicatePath(_)));
}

// =============================================================================
// Reserved path component tests (BUG-2)
// =============================================================================

#[test]
fn reject_dot_component() {
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/.".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidPath(_)));
}

#[test]
fn reject_dotdot_component() {
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/a".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/a/..".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"x".to_vec()),
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidPath(_)));
}

// =============================================================================
// NUL byte rejection test (BUG-3)
// =============================================================================

#[test]
fn reject_nul_in_path() {
    let err = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/ab\0cd".into(),
            metadata: meta(0o100_644),
            body: Body::RegularFile(b"data".to_vec()),
        },
    ])
    .unwrap_err();
    assert!(matches!(err, amla_erofs::ErofsError::InvalidPath(_)));
}

// =============================================================================
// resolve("") test (BUG-4)
// =============================================================================

#[test]
fn resolve_empty_string_errors() {
    let image = build_minimal_image();
    let fs = ErofsImage::new(&image).unwrap();
    assert!(fs.resolve("").is_err());
}

// =============================================================================
// Symlink uid/gid test (INCON-4)
// =============================================================================

#[test]
fn symlink_preserves_uid_gid() {
    let image = build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/link".into(),
            metadata: meta_owned(0o120_777, 1000, 1000),
            body: Body::Symlink("target".into()),
        },
    ])
    .unwrap()
    .into_vec();

    let fs = ErofsImage::new(&image).unwrap();
    let nid = fs.resolve("/link").unwrap();
    let info = fs.inode(nid).unwrap();
    assert!(info.is_symlink());
    assert_eq!(info.uid, 1000);
    assert_eq!(info.gid, 1000);
}
