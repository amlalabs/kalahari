// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Virtio RNG device — provides entropy to the guest.
//!
//! Single queue, no config. The entropy source is typed so production,
//! deterministic, and fork-derived entropy policies can be selected by the VMM
//! instead of being hidden inside queue processing.

#[cfg(test)]
mod tests;

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{DEVICE_ID_RNG, QueueView, QueueViolation, VIRTIO_F_VERSION_1, VirtioDevice};

/// Maximum entropy bytes returned per writable descriptor, irrespective of
/// the guest-supplied `slice.len`. A guest asking for more gets a short read,
/// which is spec-compliant for virtio-rng (§5.4: the device MAY fill fewer
/// bytes than requested). This is the structural cap that prevents a
/// malicious guest from driving a multi-GiB fill.
const RNG_MAX_BYTES_PER_DESC: u32 = 64 * 1024;
const RNG_MAX_BYTES_PER_CHAIN: usize = RNG_MAX_BYTES_PER_DESC as usize;

/// Entropy source failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("entropy source failed")
    }
}

impl std::error::Error for EntropyError {}

/// Entropy source used by the virtio-rng device.
pub trait EntropySource {
    /// Fill `dst` with entropy or report failure.
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), EntropyError>;
}

/// Host operating-system entropy source.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostEntropy;

impl EntropySource for HostEntropy {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(dst).map_err(|_| EntropyError)
    }
}

/// Virtio entropy device.
///
/// The source is part of the device value rather than hidden global behavior,
/// which lets the VMM select host, deterministic, or fork-derived entropy
/// policy explicitly.
#[derive(Debug, Clone)]
pub struct Rng<S = HostEntropy> {
    entropy: S,
}

impl Rng<HostEntropy> {
    /// Create an RNG device using host operating-system entropy.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_entropy(HostEntropy)
    }
}

impl Default for Rng<HostEntropy> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Rng<S> {
    /// Create an RNG device from an explicit entropy source.
    #[must_use]
    pub const fn with_entropy(entropy: S) -> Self {
        Self { entropy }
    }
}

impl<M, S> VirtioDevice<M> for Rng<S>
where
    M: GuestMemory,
    S: EntropySource,
{
    fn device_id(&self) -> u32 {
        DEVICE_ID_RNG
    }

    fn queue_count(&self) -> usize {
        1
    }

    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn process_queue(
        &mut self,
        _queue_idx: usize,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_writable()?;
            let mut response = Vec::new();
            for slice in chain.descriptors() {
                if response.len() >= RNG_MAX_BYTES_PER_CHAIN {
                    break;
                }
                if slice.is_empty() {
                    continue;
                }
                let target = (slice.len() as usize)
                    .min(RNG_MAX_BYTES_PER_DESC as usize)
                    .min(RNG_MAX_BYTES_PER_CHAIN - response.len());
                let start = response.len();
                response.resize(start + target, 0);
                self.entropy.fill(&mut response[start..]).map_err(|_| {
                    QueueViolation::DeviceOperationFailed {
                        device_id: DEVICE_ID_RNG,
                        operation: "entropy fill",
                    }
                })?;
            }

            queue.push_writable_bytes(chain, &response)?;
        }
        Ok(())
    }
}
