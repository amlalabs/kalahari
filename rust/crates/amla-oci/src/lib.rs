#![forbid(unsafe_code)]
//! OCI image importer.
//!
//! Pulls images from registries or the local Docker daemon and writes
//! each layer as an EROFS blob into a [`ContainerStore`].

pub mod docker_daemon;
pub mod erofs;
pub mod media_types;
pub mod progress;
pub mod reference;
pub mod registry;

pub(crate) use amla_container_store::host_arch as current_arch;

use amla_container_store::{Backend, ContainerId, ContainerMetadata, ContainerStore, Sha256Digest};
use anyhow::{Result, bail};
use progress::Progress;
use reference::ImageSource;

pub struct ImportResult {
    pub container_id: ContainerId,
    pub manifest_digest: Sha256Digest,
    pub config: serde_json::Value,
    pub layers: Vec<Sha256Digest>,
}

/// Backend-specific import result.
pub struct BackendResult {
    pub config: serde_json::Value,
    pub layers: Vec<Sha256Digest>,
    pub manifest_digest: Sha256Digest,
}

/// Import strategy for a particular image source.
pub trait ImageBackend: Send + Sync {
    fn import<B: Backend, P: Progress>(
        &self,
        store: &ContainerStore<B>,
        progress: &P,
    ) -> impl std::future::Future<Output = Result<BackendResult>> + Send
    where
        B::Writer: 'static;
}

/// Top-level import: dispatches to the right backend, writes metadata,
/// sets as default.
pub async fn import<B: Backend, P: Progress>(
    source: &ImageSource,
    store: &ContainerStore<B>,
    progress: &P,
) -> Result<ImportResult>
where
    B::Writer: 'static,
{
    let source_str = source.to_string();
    let result = source.import(store, progress).await?;

    // Convert Docker image config → OCI runtime config before storing.
    // Everything downstream (container store, guest init) sees only the
    // OCI runtime format.
    let runtime_config = docker_daemon::docker_image_config_to_runtime(&result.config);

    // Extract architecture/os from the Docker image config top-level.
    // These are required fields in the OCI image spec; if either is missing
    // we refuse the import rather than guessing.
    let architecture = result
        .config
        .get("architecture")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("image config missing required `architecture` field"))?
        .to_string();
    let os = result
        .config
        .get("os")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("image config missing required `os` field"))?
        .to_string();

    // Refuse wrong-arch imports explicitly. The registry backend already
    // picks the right manifest, but docker-archive / oci-archive / daemon
    // backends hand us whatever the source had.
    let host_arch = current_arch();
    if architecture != host_arch || os != "linux" {
        bail!(
            "image is {os}/{architecture} but host is linux/{host_arch} — refusing to import; \
             re-fetch with a matching architecture"
        );
    }

    let cid = ContainerId::new(&source_str, &result.manifest_digest);

    let metadata = ContainerMetadata {
        source: source_str,
        architecture,
        os,
        config: runtime_config,
        layers: result.layers,
    };
    store.write_metadata(&result.manifest_digest, &metadata)?;
    store.set_default(&result.manifest_digest)?;
    let ContainerMetadata { config, layers, .. } = metadata;

    Ok(ImportResult {
        container_id: cid,
        manifest_digest: result.manifest_digest,
        config,
        layers,
    })
}

impl ImageBackend for ImageSource {
    async fn import<B: Backend, P: Progress>(
        &self,
        store: &ContainerStore<B>,
        progress: &P,
    ) -> Result<BackendResult>
    where
        B::Writer: 'static,
    {
        match self {
            Self::Registry(image_ref) => {
                registry::RegistryBackend::new(image_ref.clone())
                    .import(store, progress)
                    .await
            }
            #[cfg(unix)]
            Self::DockerDaemon { reference } => {
                docker_daemon::DaemonBackend::new(reference)
                    .import(store, progress)
                    .await
            }
            #[cfg(not(unix))]
            Self::DockerDaemon { .. } => bail!("Docker daemon import requires Unix"),
            Self::DockerArchive { path, .. } => {
                docker_daemon::ArchiveBackend::new(path)
                    .import(store, progress)
                    .await
            }
            _ => bail!("unsupported source: {self}"),
        }
    }
}

// ── Shared helpers ───────────────────────────────────────────────────────

/// Return a streaming reader that decompresses gzip on the fly, or
/// passes through raw tar data unchanged. No intermediate buffer.
///
/// Accepts any `Read` — works with both byte slices and streaming pipes.
/// Peeks at the first two bytes to detect gzip magic.
pub fn streaming_decompress_reader<R: std::io::Read + Send>(
    reader: R,
) -> impl std::io::Read + Send {
    use std::io::BufRead;
    let mut buf = std::io::BufReader::new(reader);
    let is_gzip = buf
        .fill_buf()
        .ok()
        .is_some_and(|b| b.len() >= 2 && b[0] == 0x1f && b[1] == 0x8b);
    if is_gzip {
        StreamingDecompressReader::Gzip(flate2::read::GzDecoder::new(buf))
    } else {
        StreamingDecompressReader::Plain(buf)
    }
}

enum StreamingDecompressReader<R> {
    Gzip(flate2::read::GzDecoder<std::io::BufReader<R>>),
    Plain(std::io::BufReader<R>),
}

impl<R: std::io::Read> std::io::Read for StreamingDecompressReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Gzip(reader) => reader.read(out),
            Self::Plain(reader) => reader.read(out),
        }
    }
}
