//! OCI registry client — pulls images and writes layers as EROFS blobs.
//!
//! Layers are streamed end-to-end: HTTP response chunks flow through a
//! pipe into gzip decompression → tar parsing → EROFS building, with no
//! intermediate buffering of the compressed or decompressed data.

use std::sync::Arc;

use amla_container_store::{Backend, ContainerStore, Sha256Digest};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;

use crate::media_types;
use crate::progress::{LayerProgress, Progress};
use crate::reference::ImageReference;
use crate::{BackendResult, ImageBackend};

// ── Registry backend ─────────────────────────────────────────────────────

pub struct RegistryBackend {
    image_ref: ImageReference,
}

impl RegistryBackend {
    pub const fn new(image_ref: ImageReference) -> Self {
        Self { image_ref }
    }
}

impl ImageBackend for RegistryBackend {
    async fn import<B: Backend, P: Progress>(
        &self,
        store: &ContainerStore<B>,
        progress: &P,
    ) -> Result<BackendResult>
    where
        B::Writer: 'static,
    {
        registry_import(&self.image_ref, store, progress).await
    }
}

async fn registry_import<B: Backend, P: Progress>(
    image_ref: &ImageReference,
    store: &ContainerStore<B>,
    progress: &P,
) -> Result<BackendResult>
where
    B::Writer: 'static,
{
    let client = reqwest::Client::builder()
        .user_agent("amla-oci/0.1")
        .build()?;

    progress.message(&format!("Fetching manifest for {image_ref}"));
    let (manifest, manifest_digest) = fetch_manifest(&client, image_ref).await?;

    progress.message(&format!(
        "Fetching config {}",
        short(&manifest.config.digest)
    ));
    let config_bytes = fetch_blob_bytes(&client, image_ref, &manifest.config.digest).await?;
    let config: serde_json::Value = serde_json::from_slice(&config_bytes)?;

    let total = manifest.layers.len();
    let mut layers = Vec::with_capacity(total);
    let mut to_download = Vec::new();

    for (i, desc) in manifest.layers.iter().enumerate() {
        let digest = Sha256Digest::parse(&desc.digest)?;
        layers.push(digest);

        if store.has_blob(&digest) {
            progress.layer_cached(&digest, i + 1, total);
        } else {
            to_download.push((i, desc, digest));
        }
    }

    if !to_download.is_empty() {
        let client = Arc::new(client);
        let image_ref = Arc::new(image_ref.clone());
        let mut tasks = JoinSet::new();

        for (i, desc, digest) in &to_download {
            let lp = progress.layer_start(digest, i + 1, total, desc.size);

            let client = Arc::clone(&client);
            let image_ref = Arc::clone(&image_ref);
            let digest_str = desc.digest.clone();
            let digest = *digest;
            let blob = store.blob_writer(&digest)?;

            tasks.spawn(async move {
                stream_layer_to_erofs(&client, &image_ref, &digest_str, blob, &lp).await?;
                lp.finish();
                Ok::<_, anyhow::Error>(digest)
            });
        }

        while let Some(result) = tasks.join_next().await {
            result.context("download task panicked")??;
        }
    }

    Ok(BackendResult {
        config,
        layers,
        manifest_digest,
    })
}

// ── Streaming layer pipeline ────────────────────────────────────────────

/// Download a layer and build EROFS in a single streaming pipeline:
///
/// ```text
/// HTTP chunks ──→ pipe ──→ GzDecoder ──→ tar::Archive ──→ ErofsWriter
///   (async)         │          (sync, in spawn_blocking)
///                   └── tokio::io::duplex bridge
/// ```
///
/// No intermediate buffer for compressed or decompressed data.
async fn stream_layer_to_erofs(
    client: &reqwest::Client,
    image_ref: &ImageReference,
    digest: &str,
    blob: impl amla_container_store::Finalize + 'static,
    lp: &(impl LayerProgress + ?Sized),
) -> Result<()> {
    let url = format!(
        "{}/{}/blobs/{}",
        image_ref.api_base(),
        image_ref.repository,
        digest,
    );
    let resp = authed_get_response(client, image_ref, &url).await?;

    // Reject HTML error pages
    if let Some(ct) = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        && (ct.contains("text/html") || ct.contains("text/plain"))
    {
        bail!(
            "registry returned {ct} instead of blob for {digest} \
             (image may require authentication or license acceptance)"
        );
    }

    if let Some(len) = resp.content_length() {
        lp.set_total(len);
    }

    // Create a pipe: async writer (download side) → sync reader (EROFS side)
    let (pipe_reader, mut pipe_writer) = tokio::io::duplex(256 * 1024);

    let digest_owned = digest.to_string();

    // Spawn the sync EROFS builder on the blocking pool, reading from the pipe
    let builder_handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let sync_reader = tokio_util::io::SyncIoBridge::new(pipe_reader);
        let decompressor = crate::streaming_decompress_reader(sync_reader);
        crate::erofs::tar_to_erofs_blob(decompressor, blob)
            .with_context(|| format!("building EROFS for layer {digest_owned}"))
    });

    // Stream download chunks into the pipe writer (async side)
    let mut downloaded: u64 = 0;
    let mut stream = resp;
    let download_result: Result<()> = async {
        while let Some(chunk) = stream.chunk().await? {
            downloaded += chunk.len() as u64;
            lp.set_downloaded(downloaded);
            pipe_writer.write_all(&chunk).await?;
        }
        // Close the write side so the reader sees EOF
        drop(pipe_writer);
        Ok(())
    }
    .await;

    // Wait for the builder, propagate errors from both sides
    match download_result {
        Ok(()) => builder_handle
            .await
            .context("EROFS build task panicked")??,
        Err(download_err) => {
            // Download failed — drop the pipe writer (already dropped above on error path)
            // and wait for builder to finish (it will see a broken pipe / EOF). The
            // builder's own inner Err is expected noise (broken pipe from the torn-down
            // writer), so `download_err` stays the primary cause. A panic in the
            // builder task is a bug: chain it onto the download error so it isn't lost.
            let err = download_err.context("downloading layer");
            return Err(match builder_handle.await {
                Err(join_err) if join_err.is_panic() => {
                    err.context(format!("EROFS build task also panicked: {join_err}"))
                }
                _ => err,
            });
        }
    }

    Ok(())
}

// ── Manifest fetching ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestIndex {
    manifests: Vec<IndexEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexEntry {
    digest: String,
    #[serde(default)]
    media_type: Option<String>,
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    digest: String,
    #[serde(default)]
    size: Option<u64>,
}

/// Returns (manifest, `manifest_digest`). The digest is the sha256 of the
/// platform-specific manifest bytes — this matches what Docker Hub shows.
async fn fetch_manifest(
    client: &reqwest::Client,
    image_ref: &ImageReference,
) -> Result<(Manifest, Sha256Digest)> {
    let url = format!(
        "{}/{}/manifests/{}",
        image_ref.api_base(),
        image_ref.repository,
        image_ref.reference,
    );
    let accept = media_types::MANIFEST_ACCEPT.join(", ");
    let body = authed_get(client, image_ref, &url, Some(&accept)).await?;
    let raw: serde_json::Value = serde_json::from_slice(&body)?;

    let media_type = raw.get("mediaType").and_then(|v| v.as_str());

    let is_index = media_type == Some(media_types::OCI_INDEX)
        || media_type == Some(media_types::DOCKER_MANIFEST_LIST)
        || raw
            .get("manifests")
            .is_some_and(serde_json::Value::is_array);

    if is_index {
        let index: ManifestIndex = serde_json::from_value(raw)?;
        let entry = resolve_platform(&index)?;
        let url = format!(
            "{}/{}/manifests/{}",
            image_ref.api_base(),
            image_ref.repository,
            entry.digest,
        );
        let accept = entry
            .media_type
            .as_deref()
            .unwrap_or(media_types::OCI_MANIFEST);
        let body = authed_get(client, image_ref, &url, Some(accept)).await?;
        let digest = Sha256Digest::of(&body);
        Ok((serde_json::from_slice(&body)?, digest))
    } else {
        let digest = Sha256Digest::of(&body);
        Ok((serde_json::from_value(raw)?, digest))
    }
}

fn resolve_platform(index: &ManifestIndex) -> Result<&IndexEntry> {
    let arch = crate::current_arch();
    index
        .manifests
        .iter()
        .find(|e| {
            e.platform
                .as_ref()
                .is_some_and(|p| p.architecture == arch && p.os == "linux")
        })
        .with_context(|| {
            let available: Vec<String> = index
                .manifests
                .iter()
                .filter_map(|e| e.platform.as_ref())
                .map(|p| format!("{}/{}", p.os, p.architecture))
                .collect();
            format!(
                "no manifest for linux/{arch} in index; available platforms: [{}]",
                available.join(", ")
            )
        })
}

// ── HTTP helpers ─────────────────────────────────────────────────────────

async fn fetch_blob_bytes(
    client: &reqwest::Client,
    image_ref: &ImageReference,
    digest: &str,
) -> Result<Vec<u8>> {
    let url = format!(
        "{}/{}/blobs/{}",
        image_ref.api_base(),
        image_ref.repository,
        digest,
    );
    authed_get(client, image_ref, &url, None).await
}

async fn authed_get(
    client: &reqwest::Client,
    image_ref: &ImageReference,
    url: &str,
    accept: Option<&str>,
) -> Result<Vec<u8>> {
    let mut req = client.get(url);
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    let resp = req.send().await.context("HTTP request failed")?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let token = acquire_token(client, &challenge, image_ref).await?;
        let mut req = client.get(url).bearer_auth(&token);
        if let Some(a) = accept {
            req = req.header("Accept", a);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            bail!("registry returned {} for {url}", resp.status());
        }
        Ok(resp.bytes().await?.to_vec())
    } else if resp.status().is_success() {
        Ok(resp.bytes().await?.to_vec())
    } else {
        bail!("registry returned {} for {url}", resp.status());
    }
}

async fn authed_get_response(
    client: &reqwest::Client,
    image_ref: &ImageReference,
    url: &str,
) -> Result<reqwest::Response> {
    let resp = client
        .get(url)
        .send()
        .await
        .context("HTTP request failed")?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let token = acquire_token(client, &challenge, image_ref).await?;
        let resp = client.get(url).bearer_auth(&token).send().await?;
        if !resp.status().is_success() {
            bail!("registry returned {} for {url}", resp.status());
        }
        Ok(resp)
    } else if resp.status().is_success() {
        Ok(resp)
    } else {
        bail!("registry returned {} for {url}", resp.status());
    }
}

async fn acquire_token(
    client: &reqwest::Client,
    challenge: &str,
    image_ref: &ImageReference,
) -> Result<String> {
    let realm = extract_param(challenge, "realm").context("no realm in WWW-Authenticate")?;
    let service = extract_param(challenge, "service").unwrap_or_default();
    let scope = extract_param(challenge, "scope")
        .unwrap_or_else(|| format!("repository:{}:pull", image_ref.repository));

    let url = reqwest::Url::parse_with_params(
        &realm,
        &[("scope", scope.as_str()), ("service", service.as_str())],
    )
    .context("building token URL")?;

    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        bail!("token endpoint returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(serde_json::Value::as_str)
        .map(String::from)
        .context("no token in auth response")
}

fn extract_param(header: &str, key: &str) -> Option<String> {
    let pattern = format!("{key}=\"");
    let start = header.find(&pattern)? + pattern.len();
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_string())
}

fn short(digest: &str) -> &str {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    if hex.len() > 12 { &hex[..12] } else { hex }
}
