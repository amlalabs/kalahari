//! OCI and Docker registry media type constants.

// OCI image spec
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
pub const OCI_LAYER_TAR_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

// Docker v2 schema 2
pub const DOCKER_MANIFEST_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_LAYER_TAR_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
pub const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";

/// All manifest media types we accept.
pub const MANIFEST_ACCEPT: &[&str] = &[
    OCI_MANIFEST,
    OCI_INDEX,
    DOCKER_MANIFEST_V2,
    DOCKER_MANIFEST_LIST,
];
