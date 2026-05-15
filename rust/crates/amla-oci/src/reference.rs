//! OCI image reference parsing with skopeo-compatible transport syntax.
//!
//! Supported transports:
//! - `docker://registry/repo:tag` — pull from OCI registry
//! - `docker-archive:/path/to/image.tar` — `docker save` tar
//! - `oci:/path/to/dir[:tag]` — OCI image layout directory
//! - `oci-archive:/path/to/file.tar[:tag]` — OCI image layout tar
//! - `docker-daemon:image:tag` — read from local Docker daemon
//! - bare `image:tag` — shorthand for `docker://image:tag`

use std::path::PathBuf;

/// A parsed image source — transport + location.
#[derive(Debug, Clone)]
pub enum ImageSource {
    /// Pull from an OCI/Docker registry.
    Registry(ImageReference),
    /// Read from a `docker save` tar archive.
    DockerArchive {
        path: PathBuf,
        /// Optional image reference to select (when tar contains multiple images).
        reference: Option<String>,
    },
    /// Read from an OCI image layout directory.
    OciLayout {
        path: PathBuf,
        /// Optional tag (defaults to resolving from index.json).
        tag: Option<String>,
    },
    /// Read from an OCI image layout tar archive.
    OciArchive {
        path: PathBuf,
        /// Optional tag.
        tag: Option<String>,
    },
    /// Read from the local Docker daemon.
    DockerDaemon {
        /// Image reference (e.g. `myimage:latest` or `sha256:...`).
        reference: String,
    },
}

impl ImageSource {
    /// Parse a skopeo-style image source string.
    ///
    /// If no transport prefix is present, defaults to `docker://`.
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let input = input.trim();
        anyhow::ensure!(!input.is_empty(), "empty image source");

        if let Some(rest) = input.strip_prefix("docker://") {
            let image_ref = ImageReference::parse(rest)?;
            return Ok(Self::Registry(image_ref));
        }

        if let Some(rest) = input.strip_prefix("docker-archive:") {
            let (path, reference) = split_path_reference(rest);
            return Ok(Self::DockerArchive {
                path: PathBuf::from(path),
                reference,
            });
        }

        if let Some(rest) = input.strip_prefix("oci-archive:") {
            let (path, tag) = split_path_tag(rest);
            return Ok(Self::OciArchive {
                path: PathBuf::from(path),
                tag,
            });
        }

        if let Some(rest) = input.strip_prefix("oci:") {
            let (path, tag) = split_path_tag(rest);
            return Ok(Self::OciLayout {
                path: PathBuf::from(path),
                tag,
            });
        }

        if let Some(rest) = input.strip_prefix("docker-daemon:") {
            return Ok(Self::DockerDaemon {
                reference: rest.to_string(),
            });
        }

        // No transport prefix — try to detect local Docker image IDs before
        // falling back to registry pull.
        if looks_like_docker_id(input) {
            return Ok(Self::DockerDaemon {
                reference: input.to_string(),
            });
        }

        let image_ref = ImageReference::parse(input)?;
        Ok(Self::Registry(image_ref))
    }
}

/// Heuristic: does this look like a local Docker image ID rather than a
/// registry image name?
///
/// Matches the two common Docker ID formats:
/// - 12-char hex: default `docker ps` short ID (e.g. `feb7b20828c1`)
/// - 64-char hex: full sha256 digest (e.g. `sha256:...` without the prefix)
/// - `sha256:` prefixed digests
fn looks_like_docker_id(input: &str) -> bool {
    if let Some(hex) = input.strip_prefix("sha256:") {
        return hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    let is_hex = input.chars().all(|c| c.is_ascii_hexdigit());
    is_hex && (input.len() == 12 || input.len() == 64)
}

/// Split `path:tag` for oci: and oci-archive: transports.
///
/// The path may contain colons (unlikely but possible on some systems),
/// so we only split on the *last* colon that doesn't look like part of a path.
/// Heuristic: if the part after the last colon looks like a tag (no slashes,
/// no leading dot), treat it as a tag.
fn split_path_tag(s: &str) -> (&str, Option<String>) {
    if let Some(colon_pos) = s.rfind(':') {
        let after = &s[colon_pos + 1..];
        // If it looks like a tag (no slashes, non-empty, doesn't start with /),
        // treat it as one.
        if !after.is_empty() && !after.contains('/') && !after.starts_with('.') {
            return (&s[..colon_pos], Some(after.to_string()));
        }
    }
    (s, None)
}

/// Split `path:reference` for docker-archive: transport.
///
/// The reference part can be an image:tag or @source-index.
fn split_path_reference(s: &str) -> (&str, Option<String>) {
    // docker-archive: uses the first colon after the path as separator.
    // Since paths can be absolute (/foo/bar.tar), we look for a colon
    // that comes after a .tar or similar extension hint.
    // Simple approach: if there's a colon after .tar, split there.
    if let Some(tar_end) = s.find(".tar") {
        let after_tar = tar_end + 4;
        if s.len() > after_tar && s.as_bytes()[after_tar] == b':' {
            let reference = &s[after_tar + 1..];
            if !reference.is_empty() {
                return (&s[..after_tar], Some(reference.to_string()));
            }
        }
        // .tar with no colon after it
        return (s, None);
    }
    // No .tar found — try last colon heuristic
    split_path_tag(s)
}

impl std::fmt::Display for ImageSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(r) => write!(f, "docker://{r}"),
            Self::DockerArchive { path, reference } => {
                write!(f, "docker-archive:{}", path.display())?;
                if let Some(r) = reference {
                    write!(f, ":{r}")?;
                }
                Ok(())
            }
            Self::OciLayout { path, tag } => {
                write!(f, "oci:{}", path.display())?;
                if let Some(t) = tag {
                    write!(f, ":{t}")?;
                }
                Ok(())
            }
            Self::OciArchive { path, tag } => {
                write!(f, "oci-archive:{}", path.display())?;
                if let Some(t) = tag {
                    write!(f, ":{t}")?;
                }
                Ok(())
            }
            Self::DockerDaemon { reference } => write!(f, "docker-daemon:{reference}"),
        }
    }
}

// ── Registry image reference ──────────────────────────────────────────────

/// A parsed OCI registry image reference.
#[derive(Debug, Clone)]
pub struct ImageReference {
    /// Registry hostname (e.g. `registry-1.docker.io`).
    pub registry: String,
    /// Repository path (e.g. `library/ubuntu`).
    pub repository: String,
    /// Tag or digest. Digest starts with `sha256:`.
    pub reference: String,
}

impl ImageReference {
    /// Parse a Docker-style image reference (no transport prefix).
    ///
    /// Supported forms:
    /// - `ubuntu` → `registry-1.docker.io/library/ubuntu:latest`
    /// - `ubuntu:22.04` → `registry-1.docker.io/library/ubuntu:22.04`
    /// - `ghcr.io/org/repo:tag`
    /// - `registry.example.com/path/image@sha256:...`
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let input = input.trim();
        anyhow::ensure!(!input.is_empty(), "empty image reference");

        // Split off @digest or :tag from the end
        let (name, reference) = input.rfind('@').map_or_else(
            || {
                input.rfind(':').map_or_else(
                    || (input, "latest".to_string()),
                    |colon_pos| {
                        // Avoid splitting on port numbers — a colon in the registry part
                        // (before the first /) is a port, not a tag separator.
                        let first_slash = input.find('/');
                        if first_slash.is_none() || colon_pos > first_slash.unwrap_or(0) {
                            (&input[..colon_pos], input[colon_pos + 1..].to_string())
                        } else {
                            (input, "latest".to_string())
                        }
                    },
                )
            },
            |at_pos| (&input[..at_pos], input[at_pos + 1..].to_string()),
        );

        // Split registry from repository
        let (registry, repository) = split_registry_repo(name);

        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    /// The full API base URL for this registry.
    pub fn api_base(&self) -> String {
        format!("https://{}/v2", self.registry)
    }
}

/// Split a name into (registry, repository).
///
/// Docker Hub shorthand: names without a dot or colon in the first component
/// are assumed to be Docker Hub images. Single-component names get `library/`
/// prepended.
fn split_registry_repo(name: &str) -> (String, String) {
    name.find('/').map_or_else(
        || {
            (
                "registry-1.docker.io".to_string(),
                format!("library/{name}"),
            )
        },
        |slash_pos| {
            let first = &name[..slash_pos];
            if first.contains('.') || first.contains(':') || first == "localhost" {
                (normalize_registry(first), name[slash_pos + 1..].to_string())
            } else {
                ("registry-1.docker.io".to_string(), name.to_string())
            }
        },
    )
}

fn normalize_registry(host: &str) -> String {
    match host {
        "docker.io" | "index.docker.io" => "registry-1.docker.io".to_string(),
        other => other.to_string(),
    }
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sep = if self.reference.starts_with("sha256:") {
            '@'
        } else {
            ':'
        };
        write!(
            f,
            "{}/{}{sep}{}",
            self.registry, self.repository, self.reference
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // ── ImageReference tests ──

    #[test]
    fn parse_bare_name() {
        let r = ImageReference::parse("ubuntu").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_name_with_tag() {
        let r = ImageReference::parse("ubuntu:22.04").unwrap();
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.reference, "22.04");
    }

    #[test]
    fn parse_docker_hub_org() {
        let r = ImageReference::parse("myorg/myrepo:v1").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "myorg/myrepo");
        assert_eq!(r.reference, "v1");
    }

    #[test]
    fn parse_custom_registry() {
        let r = ImageReference::parse("ghcr.io/org/repo:latest").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/repo");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_digest_reference() {
        let r = ImageReference::parse("ubuntu@sha256:abc123").unwrap();
        assert_eq!(r.reference, "sha256:abc123");
    }

    #[test]
    fn parse_docker_io_alias() {
        let r = ImageReference::parse("docker.io/library/alpine:3.19").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "3.19");
    }

    #[test]
    fn parse_empty_fails() {
        assert!(ImageReference::parse("").is_err());
    }

    // ── ImageSource transport parsing ──

    #[test]
    fn source_docker_prefix() {
        let s = ImageSource::parse("docker://ghcr.io/org/repo:v2").unwrap();
        match s {
            ImageSource::Registry(r) => {
                assert_eq!(r.registry, "ghcr.io");
                assert_eq!(r.reference, "v2");
            }
            other => panic!("expected Registry, got {other:?}"),
        }
    }

    #[test]
    fn source_bare_defaults_to_registry() {
        let s = ImageSource::parse("ubuntu:22.04").unwrap();
        assert!(matches!(s, ImageSource::Registry(_)));
    }

    #[test]
    fn source_docker_archive() {
        let s = ImageSource::parse("docker-archive:/tmp/image.tar").unwrap();
        match s {
            ImageSource::DockerArchive { path, reference } => {
                assert_eq!(path.to_str().unwrap(), "/tmp/image.tar");
                assert!(reference.is_none());
            }
            other => panic!("expected DockerArchive, got {other:?}"),
        }
    }

    #[test]
    fn source_docker_archive_with_ref() {
        let s = ImageSource::parse("docker-archive:image.tar:myimage:latest").unwrap();
        match s {
            ImageSource::DockerArchive { path, reference } => {
                assert_eq!(path.to_str().unwrap(), "image.tar");
                assert_eq!(reference.unwrap(), "myimage:latest");
            }
            other => panic!("expected DockerArchive, got {other:?}"),
        }
    }

    #[test]
    fn source_oci_dir() {
        let s = ImageSource::parse("oci:/tmp/myimage").unwrap();
        match s {
            ImageSource::OciLayout { path, tag } => {
                assert_eq!(path.to_str().unwrap(), "/tmp/myimage");
                assert!(tag.is_none());
            }
            other => panic!("expected OciLayout, got {other:?}"),
        }
    }

    #[test]
    fn source_oci_dir_with_tag() {
        let s = ImageSource::parse("oci:/tmp/myimage:latest").unwrap();
        match s {
            ImageSource::OciLayout { path, tag } => {
                assert_eq!(path.to_str().unwrap(), "/tmp/myimage");
                assert_eq!(tag.unwrap(), "latest");
            }
            other => panic!("expected OciLayout, got {other:?}"),
        }
    }

    #[test]
    fn source_oci_archive() {
        let s = ImageSource::parse("oci-archive:/tmp/image.tar:v1").unwrap();
        match s {
            ImageSource::OciArchive { path, tag } => {
                assert_eq!(path.to_str().unwrap(), "/tmp/image.tar");
                assert_eq!(tag.unwrap(), "v1");
            }
            other => panic!("expected OciArchive, got {other:?}"),
        }
    }

    #[test]
    fn source_docker_daemon() {
        let s = ImageSource::parse("docker-daemon:myimage:latest").unwrap();
        match s {
            ImageSource::DockerDaemon { reference } => {
                assert_eq!(reference, "myimage:latest");
            }
            other => panic!("expected DockerDaemon, got {other:?}"),
        }
    }

    #[test]
    fn source_empty_fails() {
        assert!(ImageSource::parse("").is_err());
    }
}
