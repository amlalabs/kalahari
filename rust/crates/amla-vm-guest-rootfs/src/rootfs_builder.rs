// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Runtime EROFS rootfs assembler.
//!
//! Composes a rootfs image from the embedded `amla-guest` binary at runtime.
//! Each consumer calls [`RootfsBuilder::base()`] then optionally adds extra
//! files via [`RootfsBuilder::add_file()`].
//!
//! Returns [`amla_erofs::BuiltImage`] — callers convert to `MemHandle`
//! via `MemHandle::allocate_and_write()`.

use std::io::Cursor;

use amla_erofs::{Body, BuiltImage, Entry, ErofsError, ErofsWriter, Metadata, Permissions};

/// Standard rootfs directories and their permissions.
const ROOTFS_DIRS: &[(&str, u16)] = &[
    ("/", 0o755),
    ("/bin", 0o755),
    ("/sbin", 0o755),
    ("/usr", 0o755),
    ("/usr/bin", 0o755),
    ("/usr/sbin", 0o755),
    ("/etc", 0o755),
    ("/proc", 0o755),
    ("/sys", 0o755),
    ("/dev", 0o755),
    ("/tmp", 0o1777),
    ("/run", 0o755),
    ("/lib", 0o755),
    ("/lib/amla", 0o755),
    ("/mnt", 0o755),
    ("/mnt/amla", 0o755),
    ("/var", 0o755),
    ("/workspaces", 0o755),
];

fn dir_entry(path: &str, mode: u16) -> Entry {
    Entry {
        path: path.to_string(),
        metadata: Metadata {
            permissions: Permissions::from_mode(mode),
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
            xattrs: Vec::new(),
        },
        body: Body::Directory,
    }
}

fn file_entry(path: &str, data: &[u8], mode: u16) -> Entry {
    Entry {
        path: path.to_string(),
        metadata: Metadata {
            permissions: Permissions::from_mode(mode),
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
            xattrs: Vec::new(),
        },
        body: Body::RegularFile(data.to_vec()),
    }
}

/// Runtime EROFS rootfs assembler.
///
/// Build a base rootfs with the unified `amla-guest` binary, then add extra
/// files as needed. Call [`build()`](Self::build) to get a [`BuiltImage`].
///
/// # Example
///
/// ```no_run
/// let image = amla_guest_rootfs::RootfsBuilder::base()
///     .build()
///     .unwrap();
/// // Convert to MemHandle via MemHandle::allocate_and_write(...)
/// ```
pub struct RootfsBuilder {
    writer: ErofsWriter<Cursor<Vec<u8>>>,
    paths: std::collections::HashSet<String>,
    /// Deferred error from push calls — surfaced at `build()` time.
    error: Option<ErofsError>,
}

impl RootfsBuilder {
    /// Create a base rootfs with the unified `amla-guest` binary and
    /// standard directory structure.
    #[must_use]
    pub fn base() -> Self {
        let mut builder = Self {
            writer: ErofsWriter::new(Cursor::new(Vec::new())),
            paths: std::collections::HashSet::new(),
            error: None,
        };

        for &(path, mode) in ROOTFS_DIRS {
            builder.try_push(dir_entry(path, mode));
            builder.paths.insert(path.to_string());
        }

        builder.try_push(file_entry("/bin/amla-guest", crate::AMLA_GUEST, 0o755));
        builder
    }

    /// Add a file at an arbitrary path.
    ///
    /// Creates parent directories automatically (idempotent).
    #[must_use]
    pub fn add_file(mut self, path: &str, data: &[u8], mode: u16) -> Self {
        // Collect ancestors (leaf-to-root), then create root-to-leaf
        let mut ancestors: Vec<&str> = Vec::new();
        let mut current = std::path::Path::new(path);
        while let Some(parent) = current.parent() {
            let s = parent.to_str().unwrap_or("/");
            if s == "/" || s.is_empty() {
                break;
            }
            ancestors.push(s);
            current = parent;
        }
        for ancestor in ancestors.into_iter().rev() {
            if !self.paths.contains(ancestor) {
                self.try_push(dir_entry(ancestor, 0o755));
                self.paths.insert(ancestor.to_string());
            }
        }
        self.try_push(file_entry(path, data, mode));
        self
    }

    /// Finalize and return a built EROFS image.
    pub fn build(self) -> Result<BuiltImage, ErofsError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        self.writer.finish_to_vec()
    }

    fn try_push(&mut self, entry: Entry) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.writer.push(entry) {
            self.error = Some(e);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn base_builds_successfully() {
        let image = RootfsBuilder::base().build().unwrap();
        assert!(image.image_size() > 1024 * 1024, "image too small");
    }

    #[test]
    fn add_file_works() {
        let image = RootfsBuilder::base()
            .add_file("/bin/test-tool", b"fake-elf-data", 0o755)
            .build()
            .unwrap();
        let fs = amla_erofs::ErofsImage::new(image.as_bytes()).unwrap();
        let nid = fs.resolve("/bin/test-tool").unwrap();
        let info = fs.inode(nid).unwrap();
        assert!(info.is_reg());
        assert_eq!(info.mode & 0o777, 0o755);
    }

    #[test]
    fn add_file_creates_parent_dirs() {
        let image = RootfsBuilder::base()
            .add_file("/test/nested/binary", b"data", 0o755)
            .build()
            .unwrap();
        let fs = amla_erofs::ErofsImage::new(image.as_bytes()).unwrap();
        let nid = fs.resolve("/test/nested/binary").unwrap();
        let info = fs.inode(nid).unwrap();
        assert!(info.is_reg());
    }

    #[test]
    fn base_has_amla_guest() {
        let image = RootfsBuilder::base().build().unwrap();
        let fs = amla_erofs::ErofsImage::new(image.as_bytes()).unwrap();

        let nid = fs
            .resolve("/bin/amla-guest")
            .unwrap_or_else(|e| panic!("/bin/amla-guest: {e}"));
        let info = fs.inode(nid).unwrap();
        assert!(info.is_reg(), "/bin/amla-guest should be a regular file");
        assert_eq!(info.mode & 0o777, 0o755);
    }

    #[test]
    fn base_has_sticky_tmp() {
        let image = RootfsBuilder::base().build().unwrap();
        let fs = amla_erofs::ErofsImage::new(image.as_bytes()).unwrap();
        let nid = fs.resolve("/tmp").unwrap();
        let info = fs.inode(nid).unwrap();
        assert_eq!(info.mode & 0o7777, 0o1777);
    }
}
