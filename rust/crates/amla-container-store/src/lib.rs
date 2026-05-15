#![forbid(unsafe_code)]
//! Content-addressable container image store.
//!
//! Stores blobs keyed by [`Sha256Digest`], plus per-image metadata.
//! Storage backend is pluggable via the [`Backend`] trait.
//!
//! # Layout (with [`FsBackend`])
//!
//! ```text
//! <store>/
//!   blobs/{hex}                     — layer blob
//!   {manifest_digest_hex}/          — per-image directory
//!     metadata.json
//!   default                         — manifest digest hex of default image
//! ```
//!
//! On disk, images are keyed by manifest digest. The human-friendly
//! [`ContainerId`] is computed at runtime from metadata + digest.

use std::fmt;
use std::io::{self, BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The host CPU architecture in OCI/Docker naming (`"amd64"` or `"arm64"`).
///
/// Used to populate [`ContainerMetadata::architecture`] at import time and
/// to check imported images against the host before booting.
#[must_use]
pub const fn host_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("unsupported target architecture")
    }
}

// ── Sha256Digest ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    pub fn of(data: &[u8]) -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::digest(data).into())
    }

    pub fn parse(s: &str) -> Result<Self> {
        let hex = s.strip_prefix("sha256:").unwrap_or(s);
        let bytes = hex::decode(hex).context("invalid hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))?;
        Ok(Self(arr))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.hex()[..12].to_string()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

// ── ContainerId ───────────────────────────────────────────────────────────

/// Human-friendly container identifier, e.g. `ubuntu_24.04_a1b2c3d4e5f6`.
/// Computed at runtime from manifest digest + stored metadata.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn new(image_name: &str, manifest_digest: &Sha256Digest) -> Self {
        Self(format!(
            "{}_{}",
            sanitize_name(image_name),
            manifest_digest.short()
        ))
    }

    pub const fn from_string(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContainerId({self})")
    }
}

fn sanitize_name(name: &str) -> String {
    let s = name.strip_prefix("docker://").unwrap_or(name);
    let s = s
        .strip_prefix("registry-1.docker.io/library/")
        .or_else(|| s.strip_prefix("docker.io/library/"))
        .or_else(|| s.strip_prefix("docker.io/"))
        .unwrap_or(s);
    let s = s.strip_prefix("docker-daemon:").unwrap_or(s);
    s.replace([':', '/', '@'], "_")
}

// ── Backend trait ─────────────────────────────────────────────────────────

pub trait Finalize: Write + Seek + Send {
    fn commit(self) -> Result<()>;
}

/// Storage backend. All paths are relative to the store root.
pub trait Backend: Sync {
    type Writer: Finalize;
    fn exists(&self, path: &Path) -> bool;
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    fn create(&self, path: &Path) -> Result<Self::Writer>;
    /// Delete a file. Returns `Ok(())` if the file didn't exist.
    fn delete(&self, path: &Path) -> Result<()>;
    fn absolute_path(&self, path: &Path) -> PathBuf;
    fn list_dirs(&self, path: &Path) -> Result<Vec<String>>;
}

// ── MemBackend ────────────────────────────────────────────────────────────

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

type FileMap = Arc<Mutex<HashMap<PathBuf, Vec<u8>>>>;

/// In-memory backend for testing.
pub struct MemBackend {
    files: FileMap,
}

impl MemBackend {
    pub fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory writer: buffers in a `Cursor`, inserts into the shared map on commit.
pub struct MemWriter {
    buf: io::Cursor<Vec<u8>>,
    path: PathBuf,
    files: FileMap,
}

impl Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for MemWriter {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.buf.seek(pos)
    }
}

impl Finalize for MemWriter {
    fn commit(self) -> Result<()> {
        self.files
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
            .insert(self.path, self.buf.into_inner());
        Ok(())
    }
}

impl Backend for MemBackend {
    type Writer = MemWriter;

    fn exists(&self, path: &Path) -> bool {
        let Ok(files) = self.files.lock() else {
            return false;
        };
        files.contains_key(path)
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let files = self
            .files
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        files
            .get(path)
            .cloned()
            .with_context(|| format!("not found: {}", path.display()))
    }

    fn create(&self, path: &Path) -> Result<Self::Writer> {
        Ok(MemWriter {
            buf: io::Cursor::new(Vec::new()),
            path: path.to_path_buf(),
            files: Arc::clone(&self.files),
        })
    }

    fn delete(&self, path: &Path) -> Result<()> {
        self.files
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
            .remove(path);
        Ok(())
    }

    fn absolute_path(&self, path: &Path) -> PathBuf {
        Path::new("/mem").join(path)
    }

    fn list_dirs(&self, path: &Path) -> Result<Vec<String>> {
        // Snapshot the key set under the lock so the post-processing pass
        // doesn't hold it; `MutexGuard` is significant-Drop and the lint
        // (correctly) flags holding it across the loop unnecessarily.
        let keys: Vec<PathBuf> = {
            let files = self
                .files
                .lock()
                .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
            files.keys().cloned().collect()
        };
        let mut dirs = BTreeSet::new();
        for key in &keys {
            let rel = if path == Path::new("") {
                key.as_path()
            } else if let Ok(r) = key.strip_prefix(path) {
                r
            } else {
                continue;
            };
            if let Some(first) = rel.components().next()
                && rel.components().count() > 1
                && let Some(name) = first.as_os_str().to_str()
            {
                dirs.insert(name.to_string());
            }
        }
        Ok(dirs.into_iter().collect())
    }
}

// ── PrefixedBackend ───────────────────────────────────────────────────────

/// Wraps another backend, prepending a fixed path prefix to all operations.
///
/// Useful when a parent store owns the backend but a child (e.g.
/// `ContainerStore`) needs a scoped view of it.
pub struct PrefixedBackend<'a, B: Backend> {
    inner: &'a B,
    prefix: PathBuf,
}

impl<'a, B: Backend> PrefixedBackend<'a, B> {
    pub fn new(inner: &'a B, prefix: impl Into<PathBuf>) -> Self {
        Self {
            inner,
            prefix: prefix.into(),
        }
    }

    fn prefixed(&self, path: &Path) -> PathBuf {
        self.prefix.join(path)
    }
}

impl<B: Backend> Backend for PrefixedBackend<'_, B> {
    type Writer = B::Writer;

    fn exists(&self, path: &Path) -> bool {
        self.inner.exists(&self.prefixed(path))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        self.inner.read(&self.prefixed(path))
    }

    fn create(&self, path: &Path) -> Result<Self::Writer> {
        self.inner.create(&self.prefixed(path))
    }

    fn delete(&self, path: &Path) -> Result<()> {
        self.inner.delete(&self.prefixed(path))
    }

    fn absolute_path(&self, path: &Path) -> PathBuf {
        self.inner.absolute_path(&self.prefixed(path))
    }

    fn list_dirs(&self, path: &Path) -> Result<Vec<String>> {
        self.inner.list_dirs(&self.prefixed(path))
    }
}

// ── FsBackend ─────────────────────────────────────────────────────────────

pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn full_path(&self, rel: &Path) -> PathBuf {
        self.root.join(rel)
    }
}

pub struct AtomicFileWriter {
    inner: BufWriter<tempfile::NamedTempFile>,
    target: PathBuf,
}

impl Write for AtomicFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for AtomicFileWriter {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl Finalize for AtomicFileWriter {
    fn commit(mut self) -> Result<()> {
        self.inner.flush()?;
        self.inner
            .into_inner()
            .context("unwrapping BufWriter")?
            .persist(&self.target)
            .with_context(|| format!("persisting to {}", self.target.display()))?;
        Ok(())
    }
}

impl Backend for FsBackend {
    type Writer = AtomicFileWriter;

    fn exists(&self, path: &Path) -> bool {
        self.full_path(path).exists()
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let p = self.full_path(path);
        std::fs::read(&p).with_context(|| format!("reading {}", p.display()))
    }

    fn create(&self, path: &Path) -> Result<Self::Writer> {
        let target = self.full_path(path);
        let dir = target.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(dir)?;
        let tmp = tempfile::NamedTempFile::new_in(dir)?;
        Ok(AtomicFileWriter {
            inner: BufWriter::new(tmp),
            target,
        })
    }

    fn delete(&self, path: &Path) -> Result<()> {
        let p = self.full_path(path);
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("deleting {}", p.display())),
        }
    }

    fn absolute_path(&self, path: &Path) -> PathBuf {
        self.full_path(path)
    }

    fn list_dirs(&self, path: &Path) -> Result<Vec<String>> {
        let dir = self.full_path(path);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }
}

// ── ContainerMetadata ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMetadata {
    pub source: String,
    /// Image architecture, OCI/Docker naming (e.g. `"amd64"`, `"arm64"`).
    /// Recorded at import so mismatches can be diagnosed without re-probing
    /// the blobs. Required — old metadata without this field fails to load,
    /// forcing a re-import rather than silently continuing.
    pub architecture: String,
    /// Image OS, OCI/Docker naming (almost always `"linux"`).
    pub os: String,
    pub config: serde_json::Value,
    pub layers: Vec<Sha256Digest>,
}

// ── ContainerStore ────────────────────────────────────────────────────────

pub struct StoredImage {
    pub manifest_digest: Sha256Digest,
    pub container_id: ContainerId,
    pub metadata: ContainerMetadata,
}

pub struct ContainerStore<B: Backend> {
    backend: B,
}

impl ContainerStore<FsBackend> {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir.join("blobs"))?;
        Ok(Self {
            backend: FsBackend {
                root: dir.to_path_buf(),
            },
        })
    }
}

impl<B: Backend> ContainerStore<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    // ── Blobs ─────────────────────────────────────────────────────────

    fn blob_rel_path(digest: &Sha256Digest) -> PathBuf {
        Path::new("blobs").join(digest.hex())
    }

    pub fn has_blob(&self, digest: &Sha256Digest) -> bool {
        self.backend.exists(&Self::blob_rel_path(digest))
    }

    pub fn blob_path(&self, digest: &Sha256Digest) -> PathBuf {
        self.backend.absolute_path(&Self::blob_rel_path(digest))
    }

    pub fn blob_writer(&self, digest: &Sha256Digest) -> Result<B::Writer> {
        self.backend.create(&Self::blob_rel_path(digest))
    }

    // ── Images ────────────────────────────────────────────────────────

    fn image_metadata_path(manifest_digest: &Sha256Digest) -> PathBuf {
        Path::new(&manifest_digest.hex()).join("metadata.json")
    }

    pub fn write_metadata(
        &self,
        manifest_digest: &Sha256Digest,
        meta: &ContainerMetadata,
    ) -> Result<()> {
        let data = serde_json::to_vec_pretty(meta)?;
        let mut w = self
            .backend
            .create(&Self::image_metadata_path(manifest_digest))?;
        w.write_all(&data)?;
        w.commit()
    }

    pub fn read_metadata(&self, manifest_digest: &Sha256Digest) -> Result<ContainerMetadata> {
        let data = self
            .backend
            .read(&Self::image_metadata_path(manifest_digest))?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// List all stored images.
    pub fn list(&self) -> Result<Vec<StoredImage>> {
        let dirs = self.backend.list_dirs(Path::new(""))?;
        let mut images = Vec::new();
        for name in dirs {
            if name == "blobs" {
                continue;
            }
            let Ok(digest) = Sha256Digest::parse(&name) else {
                continue;
            };
            let meta = match self.read_metadata(&digest) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("warning: skipping image {name}: {e}");
                    continue;
                }
            };
            let cid = ContainerId::new(&meta.source, &digest);
            images.push(StoredImage {
                manifest_digest: digest,
                container_id: cid,
                metadata: meta,
            });
        }
        Ok(images)
    }

    // ── Default image ─────────────────────────────────────────────────

    pub fn default_image(&self) -> Result<Option<Sha256Digest>> {
        let data = match self.backend.read(Path::new("default")) {
            Ok(d) => d,
            Err(e) => {
                // File not found → no default set (not an error).
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let hex = std::str::from_utf8(&data)
            .context("default image file is not valid UTF-8")?
            .trim();
        if hex.is_empty() {
            return Ok(None);
        }
        Ok(Some(Sha256Digest::parse(hex).map_err(|e| {
            anyhow::anyhow!("default image file has invalid digest: {e}")
        })?))
    }

    pub fn set_default(&self, manifest_digest: &Sha256Digest) -> Result<()> {
        let mut w = self.backend.create(Path::new("default"))?;
        w.write_all(manifest_digest.hex().as_bytes())?;
        w.write_all(b"\n")?;
        w.commit()
    }

    // ── Per-key default image ────────────────────────────────────────

    /// Read the default image for a specific key (e.g. an agent type).
    ///
    /// Stored in `default.{key}` alongside the global `default` file.
    pub fn default_image_for(&self, key: &str) -> Result<Option<Sha256Digest>> {
        let path = PathBuf::from(format!("default.{key}"));
        let data = match self.backend.read(&path) {
            Ok(d) => d,
            Err(e) => {
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let hex = std::str::from_utf8(&data)
            .context("default image file is not valid UTF-8")?
            .trim();
        if hex.is_empty() {
            return Ok(None);
        }
        Ok(Some(Sha256Digest::parse(hex).map_err(|e| {
            anyhow::anyhow!("default.{key} has invalid digest: {e}")
        })?))
    }

    /// Set the default image for a specific key (e.g. an agent type).
    pub fn set_default_for(&self, key: &str, manifest_digest: &Sha256Digest) -> Result<()> {
        let path = PathBuf::from(format!("default.{key}"));
        let mut w = self.backend.create(&path)?;
        w.write_all(manifest_digest.hex().as_bytes())?;
        w.write_all(b"\n")?;
        w.commit()
    }

    /// Clear the per-key default image.
    pub fn clear_default_for(&self, key: &str) -> Result<()> {
        let path = PathBuf::from(format!("default.{key}"));
        self.backend.delete(&path)
    }
}
