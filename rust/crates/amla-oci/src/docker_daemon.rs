//! Import images from the local Docker daemon via the Engine API,
//! or from a `docker save` tar archive.
//!
//! Also provides [`docker_image_config_to_runtime`] for converting Docker
//! image configs to OCI runtime spec format.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use amla_container_store::{Backend, ContainerStore, Sha256Digest};
use anyhow::{Context, Result, bail};

use crate::progress::{LayerProgress, Progress};
use crate::{BackendResult, ImageBackend};

// ── Docker daemon backend ────────────────────────────────────────────────

pub struct DaemonBackend {
    reference: String,
}

impl DaemonBackend {
    pub fn new(reference: &str) -> Self {
        Self {
            reference: reference.to_string(),
        }
    }
}

impl ImageBackend for DaemonBackend {
    #[cfg(unix)]
    async fn import<B: Backend, P: Progress>(
        &self,
        store: &ContainerStore<B>,
        progress: &P,
    ) -> Result<BackendResult>
    where
        B::Writer: 'static,
    {
        daemon_import(&self.reference, store, progress).await
    }

    #[cfg(not(unix))]
    async fn import<B: Backend, P: Progress>(
        &self,
        _store: &ContainerStore<B>,
        _progress: &P,
    ) -> Result<BackendResult>
    where
        B::Writer: 'static,
    {
        bail!("Docker daemon import requires Unix")
    }
}

#[cfg(unix)]
async fn daemon_import<B: Backend, P: Progress>(
    reference: &str,
    store: &ContainerStore<B>,
    progress: &P,
) -> Result<BackendResult> {
    progress.message(&format!("Exporting {reference} from Docker daemon..."));

    let mut sock = tokio::net::UnixStream::connect("/var/run/docker.sock")
        .await
        .context("connecting to /var/run/docker.sock")?;

    let request = format!("GET /images/{reference}/get HTTP/1.1\r\nHost: localhost\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut sock, request.as_bytes()).await?;

    let wait_lp = progress.layer_start(&Sha256Digest::of(reference.as_bytes()), 0, 0, None);
    wait_lp.set_phase("waiting for Docker to prepare image");

    let (headers, leftover) = read_http_headers(&mut sock).await?;
    let status_line = headers
        .lines()
        .next()
        .context("empty HTTP response from Docker daemon")?;
    if !status_line.contains("200") {
        bail!("Docker daemon returned: {status_line}");
    }

    let headers_lower = headers.to_ascii_lowercase();
    let chunked = headers_lower.contains("transfer-encoding: chunked");
    let content_length: Option<u64> = headers_lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse())
        .transpose()
        .context("invalid Content-Length header from Docker daemon")?;

    wait_lp.finish();

    let download_lp = progress.layer_start(
        &Sha256Digest::of(reference.as_bytes()),
        0,
        0,
        content_length,
    );
    download_lp.set_phase("downloading image tar");

    let raw = if chunked {
        read_chunked_body(&mut sock, leftover, &download_lp).await?
    } else {
        read_plain_body(&mut sock, leftover, content_length, &download_lp).await?
    };
    download_lp.finish();

    import_from_tar_bytes(&raw, store, progress)
}

// ── HTTP helpers ─────────────────────────────────────────────────────────

/// Read HTTP headers. Returns `(header_string, leftover_body_bytes)`.
#[cfg(unix)]
async fn read_http_headers(sock: &mut tokio::net::UnixStream) -> Result<(String, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 8192];
    let mut header_buf = Vec::new();

    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            bail!("connection closed while reading HTTP headers");
        }
        header_buf.extend_from_slice(&buf[..n]);

        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = String::from_utf8_lossy(&header_buf[..pos]).to_string();
            let leftover = header_buf[pos + 4..].to_vec();
            return Ok((header_str, leftover));
        }
    }
}

/// Read a plain (non-chunked) HTTP body until EOF.
#[cfg(unix)]
async fn read_plain_body(
    sock: &mut tokio::net::UnixStream,
    leftover: Vec<u8>,
    content_length: Option<u64>,
    lp: &impl LayerProgress,
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    #[allow(clippy::cast_possible_truncation)]
    let capacity = content_length.unwrap_or(0) as usize;
    let mut data = Vec::with_capacity(capacity);
    data.extend_from_slice(&leftover);
    lp.set_downloaded(data.len() as u64);

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        lp.set_downloaded(data.len() as u64);
    }
    Ok(data)
}

/// Read an HTTP chunked transfer-encoded body.
#[cfg(unix)]
async fn read_chunked_body(
    sock: &mut tokio::net::UnixStream,
    leftover: Vec<u8>,
    lp: &impl LayerProgress,
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut data = Vec::new();
    let mut pending = leftover;

    loop {
        while !pending.windows(2).any(|w| w == b"\r\n") {
            let mut buf = vec![0u8; 64 * 1024];
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                bail!("connection closed while reading chunk header");
            }
            pending.extend_from_slice(&buf[..n]);
        }

        let crlf_pos = pending
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("expected \\r\\n in chunk header")?;
        let hex_str = std::str::from_utf8(&pending[..crlf_pos])
            .context("chunk size is not valid UTF-8")?
            .trim();
        let hex_str = hex_str.split(';').next().unwrap_or(hex_str).trim();
        let chunk_size = u64::from_str_radix(hex_str, 16)
            .with_context(|| format!("invalid chunk size: {hex_str:?}"))?;

        pending = pending[crlf_pos + 2..].to_vec();

        if chunk_size == 0 {
            break;
        }

        #[allow(clippy::cast_possible_truncation)]
        let need = chunk_size as usize + 2;
        while pending.len() < need {
            let mut buf = vec![0u8; 64 * 1024];
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                bail!("connection closed mid-chunk");
            }
            pending.extend_from_slice(&buf[..n]);
        }

        #[allow(clippy::cast_possible_truncation)]
        let cs = chunk_size as usize;
        data.extend_from_slice(&pending[..cs]);
        lp.set_downloaded(data.len() as u64);
        pending = pending[need..].to_vec();
    }

    Ok(data)
}

// ── Docker archive backend ───────────────────────────────────────────────

/// Imports from a `docker save` tar file on disk.
pub struct ArchiveBackend {
    path: PathBuf,
}

impl ArchiveBackend {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl ImageBackend for ArchiveBackend {
    async fn import<B: Backend, P: Progress>(
        &self,
        store: &ContainerStore<B>,
        progress: &P,
    ) -> Result<BackendResult>
    where
        B::Writer: 'static,
    {
        progress.message(&format!("Reading archive {}", self.path.display()));
        let data = std::fs::read(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        import_from_tar_bytes(&data, store, progress)
    }
}

// ── Shared tar processing ────────────────────────────────────────────────

fn import_from_tar_bytes<B: Backend, P: Progress>(
    data: &[u8],
    store: &ContainerStore<B>,
    progress: &P,
) -> Result<BackendResult> {
    let mut archive = tar::Archive::new(data);

    let mut small_blobs: HashMap<String, Vec<u8>> = HashMap::new();
    let mut written_digests: HashMap<String, Sha256Digest> = HashMap::new();
    let mut layer_count = 0usize;

    for entry_result in archive.entries().context("reading tar")? {
        let mut entry = entry_result.context("tar entry")?;
        let path = entry.path()?.to_string_lossy().to_string();

        if let Some(hex) = path.strip_prefix("blobs/sha256/") {
            let hex = hex.trim_end_matches('/');
            if hex.len() != 64 {
                continue;
            }
            let digest = Sha256Digest::parse(hex)?;

            if store.has_blob(&digest) {
                written_digests.insert(format!("sha256:{hex}"), digest);
                continue;
            }

            #[allow(clippy::cast_possible_truncation)]
            let mut blob_data = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut blob_data)?;

            if blob_data.len() < 512 * 1024 {
                small_blobs.insert(format!("sha256:{hex}"), blob_data);
            } else {
                layer_count += 1;
                let lp =
                    progress.layer_start(&digest, layer_count, 0, Some(blob_data.len() as u64));
                lp.set_phase("building EROFS");

                let blob = store.blob_writer(&digest)?;
                crate::erofs::tar_to_erofs_blob(
                    crate::streaming_decompress_reader(std::io::Cursor::new(blob_data)),
                    blob,
                )?;
                written_digests.insert(format!("sha256:{hex}"), digest);

                lp.finish();
            }
            continue;
        }

        if path.ends_with("/layer.tar") {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw)?;
            let digest = Sha256Digest::of(&raw);
            if !store.has_blob(&digest) {
                layer_count += 1;
                let lp = progress.layer_start(&digest, layer_count, 0, Some(raw.len() as u64));
                lp.set_phase("building EROFS");

                let blob = store.blob_writer(&digest)?;
                crate::erofs::tar_to_erofs_blob(
                    crate::streaming_decompress_reader(std::io::Cursor::new(raw)),
                    blob,
                )?;

                lp.finish();
            }
            written_digests.insert(path.clone(), digest);
            continue;
        }

        if entry.size() < 1024 * 1024 {
            let mut entry_data = Vec::new();
            entry.read_to_end(&mut entry_data)?;
            small_blobs.insert(path, entry_data);
        }
    }

    resolve_manifest(&small_blobs, &written_digests, store, progress)
}

fn resolve_manifest<B: Backend, P: Progress>(
    small_blobs: &HashMap<String, Vec<u8>>,
    written_digests: &HashMap<String, Sha256Digest>,
    store: &ContainerStore<B>,
    progress: &P,
) -> Result<BackendResult> {
    let manifest_data = small_blobs
        .get("manifest.json")
        .context("no manifest.json in tar")?;
    let manifests: Vec<DockerSaveManifest> =
        serde_json::from_slice(manifest_data).context("parsing manifest.json")?;
    let manifest = manifests.first().context("empty manifest.json")?;

    let config_data = small_blobs
        .get(&manifest.config)
        .or_else(|| {
            manifest
                .config
                .strip_prefix("blobs/sha256/")
                .map(|h| format!("sha256:{h}"))
                .and_then(|k| small_blobs.get(&k))
        })
        .with_context(|| format!("config {} not found", manifest.config))?;
    let config: serde_json::Value = serde_json::from_slice(config_data)?;

    let total = manifest.layers.len();
    let mut layers = Vec::with_capacity(total);

    for (i, layer_ref) in manifest.layers.iter().enumerate() {
        if let Some(&digest) = written_digests.get(layer_ref.as_str()) {
            layers.push(digest);
        } else if let Some(data) = small_blobs.get(layer_ref.as_str()) {
            let digest_key = layer_ref
                .strip_prefix("blobs/sha256/")
                .map_or_else(|| layer_ref.clone(), |h| format!("sha256:{h}"));
            let digest =
                Sha256Digest::parse(&digest_key).unwrap_or_else(|_| Sha256Digest::of(data));

            if store.has_blob(&digest) {
                progress.layer_cached(&digest, i + 1, total);
            } else {
                let lp = progress.layer_start(&digest, i + 1, total, None);
                lp.set_phase("building EROFS");

                let blob = store.blob_writer(&digest)?;
                crate::erofs::tar_to_erofs_blob(
                    crate::streaming_decompress_reader(std::io::Cursor::new(data.clone())),
                    blob,
                )?;

                lp.finish();
            }
            layers.push(digest);
        } else {
            bail!("layer {layer_ref} not found in tar");
        }
    }

    let manifest_digest = Sha256Digest::of(manifest_data);
    Ok(BackendResult {
        config,
        layers,
        manifest_digest,
    })
}

#[derive(serde::Deserialize)]
struct DockerSaveManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

// ── Docker image config → OCI runtime config ────────────────────────────

use serde_json::{Value, json};

/// Convert a Docker image config to an OCI runtime process config.
///
/// Input: raw Docker image config JSON (with `/config/User`, `/config/Cmd`, etc.)
/// Output: OCI runtime config JSON (with `/process/args`, `/process/user`, etc.)
///
/// Named users (e.g. `"nobody"`) cannot be resolved here because we don't
/// have access to the image's `/etc/passwd`. For those, `uid`/`gid` are set
/// to 0 and the raw string is preserved in `process.user.username` so the
/// guest can resolve it after `pivot_root`.
pub fn docker_image_config_to_runtime(image_config: &Value) -> Value {
    let config = image_config.get("config");

    // args = Entrypoint ++ Cmd (Docker concatenation semantics).
    let entrypoint = config
        .and_then(|c| c.get("Entrypoint"))
        .and_then(Value::as_array);
    let cmd = config.and_then(|c| c.get("Cmd")).and_then(Value::as_array);
    let args: Vec<Value> = match (entrypoint, cmd) {
        (Some(ep), Some(c)) => ep.iter().chain(c.iter()).cloned().collect(),
        (Some(ep), None) => ep.clone(),
        (None, Some(c)) => c.clone(),
        (None, None) => vec![],
    };

    // env: array of "KEY=VALUE" strings.
    let env: Vec<Value> = config
        .and_then(|c| c.get("Env"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // cwd. Docker serializes an absent WorkingDir as the empty string rather
    // than omitting the field, so treat "" the same as missing — otherwise
    // the guest's chdir("") fails with ENOENT.
    let cwd = config
        .and_then(|c| c.get("WorkingDir"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("/");

    // user: parse Docker's string format into OCI's structured format.
    let user_str = config
        .and_then(|c| c.get("User"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let user = parse_user_field(user_str);

    json!({
        "process": {
            "args": args,
            "env": env,
            "cwd": cwd,
            "user": user,
        }
    })
}

/// Parse Docker's `User` string into an OCI runtime `user` object.
///
/// Formats: `""`, `"root"`, `"1000"`, `"1000:1000"`, `"nobody"`, `"nobody:nogroup"`.
fn parse_user_field(user: &str) -> Value {
    let user = user.trim();
    if user.is_empty() || user == "root" {
        return json!({"uid": 0, "gid": 0});
    }

    if let Some((uid_part, gid_part)) = user.split_once(':') {
        let uid = uid_part.parse::<u32>();
        let gid = gid_part.parse::<u32>();
        match (uid, gid) {
            (Ok(uid), Ok(gid)) => return json!({"uid": uid, "gid": gid}),
            // Mixed numeric/named — store the parsed value, guest resolves the rest.
            (Ok(uid), Err(_)) => return json!({"uid": uid, "gid": 0, "username": user}),
            (Err(_), Ok(gid)) => return json!({"uid": 0, "gid": gid, "username": user}),
            (Err(_), Err(_)) => return json!({"uid": 0, "gid": 0, "username": user}),
        }
    }

    if let Ok(uid) = user.parse::<u32>() {
        return json!({"uid": uid, "gid": uid});
    }

    // Named user — guest resolves via /etc/passwd after pivot_root.
    json!({"uid": 0, "gid": 0, "username": user})
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod runtime_config_tests {
    use super::*;

    #[test]
    fn empty_user() {
        let img = json!({"config": {"User": ""}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["user"]["uid"], 0);
        assert_eq!(rt["process"]["user"]["gid"], 0);
        assert!(rt["process"]["user"]["username"].is_null());
    }

    #[test]
    fn numeric_uid() {
        let img = json!({"config": {"User": "1000"}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["user"]["uid"], 1000);
        assert_eq!(rt["process"]["user"]["gid"], 1000);
    }

    #[test]
    fn uid_gid_pair() {
        let img = json!({"config": {"User": "1000:1001"}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["user"]["uid"], 1000);
        assert_eq!(rt["process"]["user"]["gid"], 1001);
    }

    #[test]
    fn named_user() {
        let img = json!({"config": {"User": "nobody"}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["user"]["uid"], 0);
        assert_eq!(rt["process"]["user"]["username"], "nobody");
    }

    #[test]
    fn numeric_uid_named_group() {
        let img = json!({"config": {"User": "1000:nogroup"}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["user"]["uid"], 1000);
        assert_eq!(rt["process"]["user"]["gid"], 0);
        assert_eq!(rt["process"]["user"]["username"], "1000:nogroup");
    }

    #[test]
    fn named_user_numeric_gid() {
        let img = json!({"config": {"User": "nobody:1001"}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["user"]["uid"], 0);
        assert_eq!(rt["process"]["user"]["gid"], 1001);
        assert_eq!(rt["process"]["user"]["username"], "nobody:1001");
    }

    #[test]
    fn entrypoint_plus_cmd() {
        let img = json!({"config": {
            "Entrypoint": ["/entrypoint.sh"],
            "Cmd": ["--flag"]
        }});
        let rt = docker_image_config_to_runtime(&img);
        let args = rt["process"]["args"].as_array().unwrap();
        assert_eq!(args, &[json!("/entrypoint.sh"), json!("--flag")]);
    }

    #[test]
    fn cmd_only() {
        let img = json!({"config": {"Cmd": ["/bin/sh", "-c", "echo hi"]}});
        let rt = docker_image_config_to_runtime(&img);
        let args = rt["process"]["args"].as_array().unwrap();
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn env_passthrough() {
        let img = json!({"config": {"Env": ["PATH=/usr/bin", "HOME=/root"]}});
        let rt = docker_image_config_to_runtime(&img);
        let env = rt["process"]["env"].as_array().unwrap();
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn missing_config() {
        let img = json!({});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["args"].as_array().unwrap().len(), 0);
        assert_eq!(rt["process"]["cwd"], "/");
        assert_eq!(rt["process"]["user"]["uid"], 0);
    }

    #[test]
    fn empty_working_dir_becomes_root() {
        // Docker serializes an absent WorkingDir as "" rather than omitting.
        // Regression: previously produced `cwd: ""`, causing chdir("") in the
        // guest to fail with ENOENT.
        let img = json!({"config": {"WorkingDir": ""}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["cwd"], "/");
    }

    #[test]
    fn working_dir_preserved_when_set() {
        let img = json!({"config": {"WorkingDir": "/app"}});
        let rt = docker_image_config_to_runtime(&img);
        assert_eq!(rt["process"]["cwd"], "/app");
    }
}
