//! Progress reporting trait for image imports.

use amla_container_store::Sha256Digest;

/// Reports progress during image import.
///
/// Implementors handle UI (progress bars, logging, etc.).
/// The library calls these methods; the binary decides how to display them.
pub trait Progress: Send + Sync {
    /// A per-layer progress handle. Must be `Send + 'static` for async tasks.
    type Layer: LayerProgress;

    /// Called when a layer download/conversion begins.
    fn layer_start(
        &self,
        digest: &Sha256Digest,
        index: usize,
        total: usize,
        size: Option<u64>,
    ) -> Self::Layer;

    /// Called when a layer is already cached (skipped).
    fn layer_cached(&self, digest: &Sha256Digest, index: usize, total: usize);

    /// Called for non-layer status messages (e.g. "Fetching manifest").
    fn message(&self, msg: &str);
}

/// Per-layer progress handle.
pub trait LayerProgress: Send + Sync + 'static {
    /// Update the total size (e.g. from Content-Length after redirect).
    fn set_total(&self, bytes: u64);

    /// Update bytes downloaded so far.
    fn set_downloaded(&self, bytes: u64);

    /// Update the current phase (e.g. "downloading", "building EROFS").
    fn set_phase(&self, phase: &str);

    /// Mark this layer as done.
    fn finish(&self);
}

/// No-op progress implementation.
pub struct NoProgress;

impl Progress for NoProgress {
    type Layer = NoLayerProgress;

    fn layer_start(&self, _: &Sha256Digest, _: usize, _: usize, _: Option<u64>) -> Self::Layer {
        NoLayerProgress
    }

    fn layer_cached(&self, _: &Sha256Digest, _: usize, _: usize) {}
    fn message(&self, _: &str) {}
}

pub struct NoLayerProgress;

impl LayerProgress for NoLayerProgress {
    fn set_total(&self, _: u64) {}
    fn set_downloaded(&self, _: u64) {}
    fn set_phase(&self, _: &str) {}
    fn finish(&self) {}
}
