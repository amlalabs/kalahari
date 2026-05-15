//! Convert a layer tar into an EROFS image.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use amla_container_store::Finalize;
use amla_erofs::{Body, DeviceKind, Entry, ErofsWriter, Metadata, Permissions, Xattr};
use anyhow::{Context, Result};

const OPAQUE_MARKER: &str = ".wh..wh..opq";
const WHITEOUT_PREFIX: &str = ".wh.";
const OVERLAY_OPAQUE_KEY: &[u8] = b"trusted.overlay.opaque";
const OVERLAY_OPAQUE_VALUE: &[u8] = b"y";

/// A directory whose tar entry has been seen (or synthesized) but not yet
/// pushed to the EROFS writer. Held back so that an opaque-directory
/// marker (`.wh..wh..opq`) seen later in the same directory can attach the
/// `trusted.overlay.opaque` xattr to the inode.
struct PendingDir {
    mode: u16,
    uid: u32,
    gid: u32,
    opaque: bool,
}

/// Build an EROFS image from a decompressed layer tar and write it into
/// `blob`, committing the blob on success.
///
/// OCI tar whiteouts are translated to overlayfs form at build time:
///
/// * Each `.wh.NAME` entry is emitted as a character device at `NAME`
///   with `rdev = 0`, which is the overlayfs marker for "this name is
///   deleted in this layer."
/// * Each `.wh..wh..opq` entry sets a `trusted.overlay.opaque=y` xattr
///   on the parent directory's EROFS inode, which is the overlayfs
///   marker for "everything from lower layers is hidden under this
///   directory."
///
/// The translation is a constant-time per-entry transform, not a merge
/// across layers. Each layer's EROFS image still describes only that
/// layer's additions, modifications, and (now) deletions.
///
/// File data is streamed from the tar entry directly into
/// [`ErofsWriter::push_file`]. Opaque whiteouts can arrive after their
/// directory already has children; in that case the EROFS builder updates the
/// directory metadata before finalizing the image rather than replaying or
/// spooling the tar.
pub fn tar_to_erofs_blob(tar_input: impl Read, mut blob: impl Finalize) -> Result<()> {
    write_erofs_from_tar(tar_input, &mut blob)?;
    blob.commit()
}

fn write_erofs_from_tar(tar_input: impl Read, blob: &mut impl Finalize) -> Result<()> {
    let mut archive = tar::Archive::new(tar_input);
    let mut erofs = ErofsWriter::new(blob);
    let mut pending_dirs: BTreeMap<String, PendingDir> = BTreeMap::new();
    let mut added_dirs: BTreeSet<String> = BTreeSet::new();

    // Root is held in pending_dirs (not pushed eagerly) so that a top-level
    // `.wh..wh..opq` can attach trusted.overlay.opaque to the root inode.
    pending_dirs.insert(
        "/".to_string(),
        PendingDir {
            mode: 0o755,
            uid: 0,
            gid: 0,
            opaque: false,
        },
    );

    let entries = archive
        .entries()
        .context("reading tar entries (is this a valid tar?)")?;
    for entry_result in entries {
        let mut entry = entry_result.context("reading next tar entry")?;
        let path = entry.path()?.to_string_lossy().to_string();
        let clean = clean_path(&path);
        if clean.is_empty() || clean == "." {
            continue;
        }
        let erofs_path = format!("/{clean}");
        let basename = clean.rsplit('/').next().unwrap_or(&clean).to_string();
        let parent = parent_of(&erofs_path);

        if basename == OPAQUE_MARKER {
            handle_opaque_marker(&parent, &mut pending_dirs, &added_dirs, &mut erofs)?;
            continue;
        }
        if let Some(target_name) = basename.strip_prefix(WHITEOUT_PREFIX) {
            handle_whiteout(
                &parent,
                target_name,
                &mut pending_dirs,
                &mut added_dirs,
                &mut erofs,
            )?;
            continue;
        }
        handle_regular_entry(
            &mut entry,
            erofs_path,
            &mut pending_dirs,
            &mut added_dirs,
            &mut erofs,
        )?;
    }

    flush_remaining_dirs(&mut pending_dirs, &mut added_dirs, &mut erofs)?;

    let (_, _stats) = erofs.finish().context("building EROFS")?;
    Ok(())
}

/// Opaque-directory marker (`.wh..wh..opq`): attach
/// `trusted.overlay.opaque=y` to the parent dir's pending entry so it
/// lands as an inline xattr on the EROFS inode at flush time.
fn handle_opaque_marker(
    parent: &str,
    pending_dirs: &mut BTreeMap<String, PendingDir>,
    added_dirs: &BTreeSet<String>,
    erofs: &mut ErofsWriter<impl std::io::Write + std::io::Seek>,
) -> Result<()> {
    if added_dirs.contains(parent) {
        erofs
            .set_xattr(
                parent,
                Xattr {
                    key: OVERLAY_OPAQUE_KEY.to_vec(),
                    value: OVERLAY_OPAQUE_VALUE.to_vec(),
                },
            )
            .context("marking pushed directory opaque")?;
    } else {
        pending_dirs
            .entry(parent.to_string())
            .or_insert(PendingDir {
                mode: 0o755,
                uid: 0,
                gid: 0,
                opaque: false,
            })
            .opaque = true;
    }
    Ok(())
}

/// Regular whiteout (`.wh.NAME`): emit a `S_IFCHR | 0` chardev with
/// `rdev = 0` at `<parent>/<NAME>`. The original tar entry's body is
/// ignored.
fn handle_whiteout(
    parent: &str,
    target_name: &str,
    pending_dirs: &mut BTreeMap<String, PendingDir>,
    added_dirs: &mut BTreeSet<String>,
    erofs: &mut ErofsWriter<impl std::io::Write + std::io::Seek>,
) -> Result<()> {
    let target_path = if parent == "/" {
        format!("/{target_name}")
    } else {
        format!("{parent}/{target_name}")
    };
    ensure_parents(&target_path, pending_dirs, added_dirs, erofs)?;
    erofs
        .push(Entry {
            path: target_path,
            metadata: meta(0, 0, 0),
            body: Body::DeviceNode {
                kind: DeviceKind::Character,
                rdev: 0,
            },
        })
        .context("pushing whiteout chardev")?;
    Ok(())
}

/// Push a file/symlink/hardlink/directory tar entry. Directories are
/// buffered in `pending_dirs` until their first child arrives or
/// end-of-tar, so that an opaque marker arriving in between can attach
/// to them.
fn handle_regular_entry(
    entry: &mut tar::Entry<'_, impl Read>,
    erofs_path: String,
    pending_dirs: &mut BTreeMap<String, PendingDir>,
    added_dirs: &mut BTreeSet<String>,
    erofs: &mut ErofsWriter<impl std::io::Write + std::io::Seek>,
) -> Result<()> {
    let header = entry.header();
    #[allow(clippy::cast_possible_truncation)]
    let mode = header.mode().unwrap_or(0o644) as u16;
    #[allow(clippy::cast_possible_truncation)]
    let uid = header.uid().unwrap_or(0) as u32;
    #[allow(clippy::cast_possible_truncation)]
    let gid = header.gid().unwrap_or(0) as u32;
    let ty = header.entry_type();

    if ty.is_dir() {
        if !added_dirs.contains(&erofs_path) {
            let opaque = pending_dirs.get(&erofs_path).is_some_and(|p| p.opaque);
            pending_dirs.insert(
                erofs_path.clone(),
                PendingDir {
                    mode,
                    uid,
                    gid,
                    opaque,
                },
            );
        }
        return Ok(());
    }

    ensure_parents(&erofs_path, pending_dirs, added_dirs, erofs)?;

    if ty.is_symlink() {
        let target = entry
            .link_name()?
            .context("symlink target")?
            .to_string_lossy()
            .to_string();
        erofs
            .push(Entry {
                path: erofs_path,
                metadata: meta(0o120_777, uid, gid),
                body: Body::Symlink(target),
            })
            .context("pushing symlink")?;
    } else if ty.is_hard_link() {
        let target = entry
            .link_name()?
            .context("hardlink target")?
            .to_string_lossy()
            .to_string();
        erofs
            .push(Entry {
                path: erofs_path,
                metadata: meta(0o100_000 | mode, uid, gid),
                body: Body::Hardlink(format!("/{}", clean_path(&target))),
            })
            .context("pushing hardlink")?;
    } else if ty.is_file() {
        let size = entry.size();
        erofs
            .push_file(erofs_path, meta(0o100_000 | mode, uid, gid), size, entry)
            .context("pushing file")?;
    }
    Ok(())
}

fn flush_remaining_dirs(
    pending_dirs: &mut BTreeMap<String, PendingDir>,
    added_dirs: &mut BTreeSet<String>,
    erofs: &mut ErofsWriter<impl std::io::Write + std::io::Seek>,
) -> Result<()> {
    let pending_paths: Vec<String> = pending_dirs.keys().cloned().collect();
    for path in pending_paths {
        ensure_parents(&format!("{path}/_"), pending_dirs, added_dirs, erofs)?;
        if !added_dirs.contains(&path)
            && let Some(p) = pending_dirs.remove(&path)
        {
            erofs
                .push(Entry {
                    path: path.clone(),
                    metadata: dir_meta(&p),
                    body: Body::Directory,
                })
                .context("flushing pending directory")?;
            added_dirs.insert(path);
        }
    }
    Ok(())
}

const fn meta(mode: u16, uid: u32, gid: u32) -> Metadata {
    Metadata {
        permissions: Permissions::from_mode(mode),
        uid,
        gid,
        mtime: 0,
        mtime_nsec: 0,
        xattrs: Vec::new(),
    }
}

fn dir_meta(p: &PendingDir) -> Metadata {
    let mut m = meta(0o040_000 | p.mode, p.uid, p.gid);
    if p.opaque {
        m.xattrs.push(Xattr {
            key: OVERLAY_OPAQUE_KEY.to_vec(),
            value: OVERLAY_OPAQUE_VALUE.to_vec(),
        });
    }
    m
}

fn ensure_parents(
    path: &str,
    pending_dirs: &mut BTreeMap<String, PendingDir>,
    added_dirs: &mut BTreeSet<String>,
    erofs: &mut ErofsWriter<impl std::io::Write + std::io::Seek>,
) -> Result<()> {
    // Collect unpushed ancestors from nearest-to-root, then flush in reverse
    // (root first). Root is treated as a real ancestor "/" so that pending
    // opacity attached to root is preserved.
    let mut ancestors: Vec<String> = Vec::new();
    let mut cur: String = path.to_string();
    loop {
        let parent = match cur.rsplit_once('/') {
            Some(("", _)) => "/".to_string(),
            Some((p, _)) => p.to_string(),
            None => break,
        };
        if added_dirs.contains(&parent) {
            break;
        }
        ancestors.push(parent.clone());
        if parent == "/" {
            break;
        }
        cur = parent;
    }
    for ancestor in ancestors.into_iter().rev() {
        flush_dir(&ancestor, pending_dirs, added_dirs, erofs)?;
    }
    Ok(())
}

fn flush_dir(
    path: &str,
    pending_dirs: &mut BTreeMap<String, PendingDir>,
    added_dirs: &mut BTreeSet<String>,
    erofs: &mut ErofsWriter<impl std::io::Write + std::io::Seek>,
) -> Result<()> {
    if added_dirs.contains(path) {
        return Ok(());
    }
    let entry = pending_dirs.remove(path).map_or_else(
        || Entry {
            path: path.to_string(),
            metadata: dir_meta(&PendingDir {
                mode: 0o755,
                uid: 0,
                gid: 0,
                opaque: false,
            }),
            body: Body::Directory,
        },
        |p| Entry {
            path: path.to_string(),
            metadata: dir_meta(&p),
            body: Body::Directory,
        },
    );
    erofs.push(entry).context("pushing directory")?;
    added_dirs.insert(path.to_string());
    Ok(())
}

fn parent_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/".to_string(),
        Some((parent, _)) => parent.to_string(),
    }
}

fn clean_path(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests should fail loudly and use compact in-memory fixtures"
)]
mod tests {
    use super::*;
    use amla_container_store::Finalize;
    use amla_erofs::ErofsImage;
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Build a tar in memory with the given entries.
    fn make_tar(entries: &[(&str, tar::EntryType, &[u8], u32)]) -> Vec<u8> {
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (path, ty, data, mode) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(*mode);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_entry_type(*ty);
                header.set_cksum();
                builder
                    .append_data(&mut header, *path, *data)
                    .expect("tar append");
            }
            builder.finish().expect("tar finish");
        }
        tar_buf
    }

    /// Cursor-backed `Finalize` adapter: lets tests run the production
    /// `tar_to_erofs_blob` against an in-memory output buffer.
    struct CursorBlob<'a> {
        inner: Cursor<&'a mut Vec<u8>>,
    }
    impl Write for CursorBlob<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    impl std::io::Seek for CursorBlob<'_> {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }
    impl Finalize for CursorBlob<'_> {
        fn commit(self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Convert a tar to EROFS bytes via the same code path the production
    /// importer uses, returning the raw EROFS image for inspection.
    fn convert(tar_bytes: &[u8]) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        let blob = CursorBlob {
            inner: Cursor::new(&mut output),
        };
        tar_to_erofs_blob(tar_bytes, blob).expect("tar_to_erofs_blob");
        output
    }

    enum TarSegment {
        Bytes {
            data: Vec<u8>,
            offset: usize,
        },
        Zeros {
            remaining: u64,
            mark_done_on_complete: bool,
        },
    }

    struct StreamingTar {
        segments: VecDeque<TarSegment>,
        done: Arc<AtomicBool>,
    }

    impl StreamingTar {
        fn with_late_opaque_marker(file_size: u64, done: Arc<AtomicBool>) -> Self {
            let mut segments = VecDeque::new();
            segments.push_back(TarSegment::Bytes {
                data: header_bytes("dir/", tar::EntryType::Directory, 0, 0o755),
                offset: 0,
            });
            segments.push_back(TarSegment::Bytes {
                data: header_bytes("dir/big", tar::EntryType::Regular, file_size, 0o644),
                offset: 0,
            });
            segments.push_back(TarSegment::Zeros {
                remaining: file_size,
                mark_done_on_complete: true,
            });
            let padding = (512 - (file_size % 512)) % 512;
            if padding > 0 {
                segments.push_back(TarSegment::Zeros {
                    remaining: padding,
                    mark_done_on_complete: false,
                });
            }
            segments.push_back(TarSegment::Bytes {
                data: header_bytes("dir/.wh..wh..opq", tar::EntryType::Regular, 0, 0o644),
                offset: 0,
            });
            segments.push_back(TarSegment::Zeros {
                remaining: 1024,
                mark_done_on_complete: false,
            });
            Self { segments, done }
        }
    }

    impl Read for StreamingTar {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let mut written = 0;
            while written < buf.len() {
                let Some(segment) = self.segments.front_mut() else {
                    break;
                };

                let (segment_done, mark_done_on_complete) = match segment {
                    TarSegment::Bytes { data, offset } => {
                        let available = data.len().saturating_sub(*offset);
                        let count = available.min(buf.len() - written);
                        buf[written..written + count]
                            .copy_from_slice(&data[*offset..*offset + count]);
                        *offset += count;
                        written += count;
                        (*offset == data.len(), false)
                    }
                    TarSegment::Zeros {
                        remaining,
                        mark_done_on_complete,
                    } => {
                        let want = u64::try_from(buf.len() - written).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "read buffer too large")
                        })?;
                        let count_u64 = (*remaining).min(want);
                        let count = usize::try_from(count_u64).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "zero segment too large")
                        })?;
                        buf[written..written + count].fill(0);
                        *remaining -= count_u64;
                        written += count;
                        (*remaining == 0, *mark_done_on_complete)
                    }
                };

                if segment_done {
                    if mark_done_on_complete {
                        self.done.store(true, Ordering::SeqCst);
                    }
                    self.segments.pop_front();
                }
            }

            Ok(written)
        }
    }

    fn header_bytes(path: &str, ty: tar::EntryType, size: u64, mode: u32) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("tar header path");
        header.set_size(size);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(ty);
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    struct ObservingBlob {
        pos: u64,
        len: u64,
        content_done: Arc<AtomicBool>,
        bytes_written_before_content_done: Arc<AtomicUsize>,
    }

    impl ObservingBlob {
        fn new(
            content_done: Arc<AtomicBool>,
            bytes_written_before_content_done: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                pos: 0,
                len: 0,
                content_done,
                bytes_written_before_content_done,
            }
        }
    }

    impl Write for ObservingBlob {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.content_done.load(Ordering::SeqCst) {
                self.bytes_written_before_content_done
                    .fetch_add(buf.len(), Ordering::SeqCst);
            }
            let count = u64::try_from(buf.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write too large"))?;
            self.pos = self
                .pos
                .checked_add(count)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "position overflow"))?;
            self.len = self.len.max(self.pos);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Seek for ObservingBlob {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            let next = match pos {
                SeekFrom::Start(offset) => offset,
                SeekFrom::Current(delta) => add_signed(self.pos, delta)?,
                SeekFrom::End(delta) => add_signed(self.len, delta)?,
            };
            self.pos = next;
            Ok(self.pos)
        }
    }

    impl Finalize for ObservingBlob {
        fn commit(self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn add_signed(base: u64, delta: i64) -> io::Result<u64> {
        if delta >= 0 {
            base.checked_add(delta.unsigned_abs()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek position overflow")
            })
        } else {
            base.checked_sub(delta.unsigned_abs())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))
        }
    }

    #[test]
    fn tar_conversion_streams_content_before_reaching_tar_end() {
        let content_done = Arc::new(AtomicBool::new(false));
        let bytes_written_before_content_done = Arc::new(AtomicUsize::new(0));
        let tar = StreamingTar::with_late_opaque_marker(8 * 1024 * 1024, Arc::clone(&content_done));
        let blob = ObservingBlob::new(
            Arc::clone(&content_done),
            Arc::clone(&bytes_written_before_content_done),
        );

        tar_to_erofs_blob(tar, blob).expect("streaming tar conversion");

        assert!(
            content_done.load(Ordering::SeqCst),
            "test tar stream should read the large file body"
        );
        assert!(
            bytes_written_before_content_done.load(Ordering::SeqCst) > 0,
            "converter wrote no output until after consuming the large file body; that implies content-sized staging"
        );
    }

    /// Walk the inline xattr blob for a given inode and look up a key,
    /// returning the value bytes if present. Mirrors the kernel parser.
    fn read_inline_xattr(image_bytes: &[u8], nid: u64, full_key: &[u8]) -> Option<Vec<u8>> {
        let _image = ErofsImage::new(image_bytes).ok()?;
        // We cannot use the public reader to see xattr blobs directly, so
        // parse the inode header out of the raw image to find the inline
        // xattr area, then walk it.
        // Inode offset and size are not exposed publicly. Instead, we use
        // the trusted-overlay convention: the xattr area sits immediately
        // after the inode struct. We derive its position by re-deriving
        // what the reader does internally.
        //
        // EROFS layout:
        //   superblock at offset 1024, meta_blkaddr * BLOCK_SIZE points to
        //   inode region. Each inode is at meta_blkaddr*BLOCK_SIZE + nid*32.
        //   We use the same mapping the writer used.
        const BLOCK_SIZE: u64 = 4096;
        const SUPERBLOCK_OFFSET: usize = 1024;
        // Per EROFS on-disk superblock layout (see SuperBlock in ondisk.rs):
        //   offset 14: root_nid (u16)
        //   offset 40: meta_blkaddr (u32)
        let meta_blkaddr = {
            let off = SUPERBLOCK_OFFSET + 40;
            let bytes: [u8; 4] = image_bytes.get(off..off + 4)?.try_into().ok()?;
            u32::from_le_bytes(bytes)
        };
        let inode_offset = u64::from(meta_blkaddr) * BLOCK_SIZE + nid * 32;
        let inode_off = usize::try_from(inode_offset).ok()?;
        // The first u16 of the inode is i_format. Bit 0 is the layout
        // family (compact=0, extended=1). For the root directory and
        // directories created by our builder, format starts as compact.
        let i_format: u16 =
            u16::from_le_bytes(image_bytes.get(inode_off..inode_off + 2)?.try_into().ok()?);
        let extended = (i_format & 0x1) == 1;
        let inode_size = if extended { 64 } else { 32 };
        // i_xattr_icount is at offset 2 (u16 le).
        let xattr_icount: u16 = u16::from_le_bytes(
            image_bytes
                .get(inode_off + 2..inode_off + 4)?
                .try_into()
                .ok()?,
        );
        if xattr_icount == 0 {
            return None;
        }
        // xattr area size = 4 * icount + 8 (per kernel: 12-byte header +
        // 4*(icount-1) for entries).
        let xattr_size = 4 * usize::from(xattr_icount) + 8;
        let xattr_start = inode_off + inode_size;
        let xattr_end = xattr_start + xattr_size;
        if xattr_end > image_bytes.len() {
            return None;
        }
        let xattr_blob = &image_bytes[xattr_start..xattr_end];
        // Skip 12-byte XattrInodeHeader (all zeros in our writer).
        // Per-entry header layout (matches `serialize_inline_xattrs`):
        //   byte 0: name_suffix_len (u8)
        //   byte 1: prefix_index (u8)
        //   bytes 2-3: value_size (u16 LE)
        let mut cur = 12;
        while cur + 4 <= xattr_blob.len() {
            let name_suffix_len = xattr_blob[cur] as usize;
            let prefix_idx = xattr_blob[cur + 1];
            let value_size =
                u16::from_le_bytes([xattr_blob[cur + 2], xattr_blob[cur + 3]]) as usize;
            let name_start = cur + 4;
            let name_end = name_start + name_suffix_len;
            let value_start = name_end;
            let value_end = value_start + value_size;
            if value_end > xattr_blob.len() {
                return None;
            }
            let name_suffix = &xattr_blob[name_start..name_end];
            // Reconstruct full key from prefix index + suffix.
            let full = match prefix_idx {
                1 => [b"user.", name_suffix].concat(),
                6 => [b"security.", name_suffix].concat(),
                7 => [b"system.", name_suffix].concat(),
                8 => [b"trusted.", name_suffix].concat(),
                _ => name_suffix.to_vec(),
            };
            if full == full_key {
                return Some(xattr_blob[value_start..value_end].to_vec());
            }
            // Advance, padding to 4-byte alignment for the next entry.
            let entry_len = 4 + name_suffix_len + value_size;
            let padded = (entry_len + 3) & !3;
            cur += padded;
        }
        None
    }

    #[test]
    fn whiteout_file_becomes_chardev_rdev_zero() {
        // Tar contains a directory and a regular whiteout marker for "gone".
        let tar = make_tar(&[
            ("dir/", tar::EntryType::Directory, b"", 0o755),
            ("dir/keep", tar::EntryType::Regular, b"hello", 0o644),
            ("dir/.wh.gone", tar::EntryType::Regular, b"", 0o644),
        ]);
        let img_bytes = convert(&tar);
        let img = ErofsImage::new(&img_bytes).expect("parse erofs");

        // Original whiteout source path must NOT exist as a regular entry.
        assert!(
            img.resolve("/dir/.wh.gone").is_err(),
            "whiteout source should be translated, not preserved"
        );

        // Translated chardev appears at /dir/gone with rdev=0.
        let nid = img.resolve("/dir/gone").expect("/dir/gone exists");
        let info = img.inode(nid).expect("inode read");
        assert!(info.is_chrdev(), "translated whiteout must be a chardev");
        assert_eq!(info.rdev_major(), 0, "whiteout chardev major must be 0");
        assert_eq!(info.rdev_minor(), 0, "whiteout chardev minor must be 0");

        // The kept file is still present.
        let keep_nid = img.resolve("/dir/keep").expect("/dir/keep exists");
        let keep_info = img.inode(keep_nid).unwrap();
        assert!(keep_info.is_reg());
    }

    #[test]
    fn opaque_marker_sets_trusted_overlay_xattr() {
        // Tar order: dir entry, then opaque marker, then a sibling file.
        // The opaque marker must mark the parent dir and not be emitted as
        // a regular entry.
        let tar = make_tar(&[
            ("dir/", tar::EntryType::Directory, b"", 0o755),
            ("dir/.wh..wh..opq", tar::EntryType::Regular, b"", 0o644),
            ("dir/file", tar::EntryType::Regular, b"x", 0o644),
        ]);
        let img_bytes = convert(&tar);
        let img = ErofsImage::new(&img_bytes).expect("parse erofs");

        // The opaque marker's tar path must NOT appear in the EROFS image.
        assert!(
            img.resolve("/dir/.wh..wh..opq").is_err(),
            "opaque marker should not appear as a regular entry"
        );

        // The dir is opaque.
        let dir_nid = img.resolve("/dir").expect("/dir exists");
        let value = read_inline_xattr(&img_bytes, dir_nid, b"trusted.overlay.opaque");
        assert_eq!(
            value.as_deref(),
            Some(&b"y"[..]),
            "opaque marker must produce trusted.overlay.opaque=y on parent dir"
        );

        // Sibling file is preserved.
        assert!(img.resolve("/dir/file").is_ok());
    }

    #[test]
    fn opaque_marker_at_root_marks_root_dir() {
        let tar = make_tar(&[
            (".wh..wh..opq", tar::EntryType::Regular, b"", 0o644),
            ("a", tar::EntryType::Regular, b"a", 0o644),
        ]);
        let img_bytes = convert(&tar);
        let img = ErofsImage::new(&img_bytes).expect("parse erofs");

        let root_nid = img.root_nid();
        let value = read_inline_xattr(&img_bytes, root_nid, b"trusted.overlay.opaque");
        assert_eq!(
            value.as_deref(),
            Some(&b"y"[..]),
            "root opaque marker must produce trusted.overlay.opaque=y on root"
        );
        assert!(img.resolve("/a").is_ok());
    }

    #[test]
    fn whiteout_at_root_translates_to_chardev() {
        let tar = make_tar(&[
            (".wh.deleted", tar::EntryType::Regular, b"", 0o644),
            ("kept", tar::EntryType::Regular, b"x", 0o644),
        ]);
        let img_bytes = convert(&tar);
        let img = ErofsImage::new(&img_bytes).expect("parse erofs");

        assert!(
            img.resolve("/.wh.deleted").is_err(),
            "whiteout source must not be preserved at root"
        );
        let nid = img.resolve("/deleted").expect("/deleted exists");
        let info = img.inode(nid).unwrap();
        assert!(info.is_chrdev());
        assert_eq!(info.rdev_major(), 0);
        assert_eq!(info.rdev_minor(), 0);
        assert!(img.resolve("/kept").is_ok());
    }

    #[test]
    fn opaque_then_dir_entry_preserves_opacity() {
        // .wh..wh..opq for "dir" appears BEFORE the dir entry itself. The
        // opaque flag should be carried across the explicit dir push.
        let tar = make_tar(&[
            ("dir/.wh..wh..opq", tar::EntryType::Regular, b"", 0o644),
            ("dir/", tar::EntryType::Directory, b"", 0o750),
            ("dir/x", tar::EntryType::Regular, b"x", 0o644),
        ]);
        let img_bytes = convert(&tar);
        let img = ErofsImage::new(&img_bytes).expect("parse erofs");

        let nid = img.resolve("/dir").expect("/dir exists");
        let value = read_inline_xattr(&img_bytes, nid, b"trusted.overlay.opaque");
        assert_eq!(value.as_deref(), Some(&b"y"[..]));
    }

    #[test]
    fn opaque_marker_after_children_marks_parent_dir() {
        // OCI opaque markers apply independently of encounter order. This
        // order previously failed after /a had already been pushed as the
        // parent of /a/b/c/foo.
        let tar = make_tar(&[
            ("a/", tar::EntryType::Directory, b"", 0o755),
            ("a/b/", tar::EntryType::Directory, b"", 0o755),
            ("a/b/c/foo", tar::EntryType::Regular, b"x", 0o644),
            ("a/.wh..wh..opq", tar::EntryType::Regular, b"", 0o644),
        ]);
        let img_bytes = convert(&tar);
        let img = ErofsImage::new(&img_bytes).expect("parse erofs");

        let a_nid = img.resolve("/a").expect("/a exists");
        let value = read_inline_xattr(&img_bytes, a_nid, b"trusted.overlay.opaque");
        assert_eq!(value.as_deref(), Some(&b"y"[..]));
        assert!(img.resolve("/a/b/c/foo").is_ok());
        assert!(img.resolve("/a/.wh..wh..opq").is_err());
    }
}
