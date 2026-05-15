// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Irqchip state (repr(C), POD).
//!
//! The irqchip section stores architecture-specific KVM state (PIC/IOAPIC/PIT
//! on x86, GIC on ARM64) as an opaque byte region.

use bytemuck::{Pod, Zeroable};

/// Size of the architecture-specific irqchip blob (256 KiB).
///
/// Must be large enough for the GIC state with `MAX_VCPUS` redistributors
/// and CPU interfaces. Apple's HVF GIC state (via `hv_gic_state_create`)
/// is ~126 KiB for a single vCPU; 256 KiB provides headroom.
pub const IRQCHIP_BLOB_SIZE: usize = 262_144;

/// Complete irqchip section layout.
///
/// The `arch_blob` stores the raw architecture-specific KVM state.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct IrqchipSectionState {
    /// Number of valid bytes in `arch_blob`.
    arch_blob_len: u32,
    /// Padding for alignment.
    pad: u32,
    /// Architecture-specific irqchip state (raw bytes).
    arch_blob: [u8; IRQCHIP_BLOB_SIZE],
}

impl IrqchipSectionState {
    /// Validate the irqchip section's host-owned shape.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.arch_blob_len as usize > IRQCHIP_BLOB_SIZE {
            return Err("irqchip arch blob length exceeds section capacity");
        }
        if self.pad != 0 {
            return Err("irqchip padding is nonzero");
        }
        Ok(())
    }

    /// Return the valid architecture-specific irqchip blob bytes.
    pub fn arch_blob(&self) -> Result<&[u8], &'static str> {
        self.validate()?;
        Ok(&self.arch_blob[..self.arch_blob_len as usize])
    }

    /// Replace the architecture-specific irqchip blob and zero stale bytes.
    pub fn set_arch_blob(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > IRQCHIP_BLOB_SIZE {
            return Err("irqchip arch blob length exceeds section capacity");
        }
        self.arch_blob.fill(0);
        self.arch_blob[..data.len()].copy_from_slice(data);
        self.arch_blob_len =
            u32::try_from(data.len()).map_err(|_| "irqchip arch blob length exceeds u32")?;
        self.pad = 0;
        Ok(())
    }

    /// Replace the blob using a writer that fills the fixed backing storage.
    pub fn write_arch_blob_with(
        &mut self,
        write: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), &'static str> {
        self.arch_blob.fill(0);
        let written = write(&mut self.arch_blob);
        if written > IRQCHIP_BLOB_SIZE {
            self.arch_blob.fill(0);
            self.arch_blob_len = 0;
            return Err("irqchip arch blob writer exceeded section capacity");
        }
        self.arch_blob_len =
            u32::try_from(written).map_err(|_| "irqchip arch blob length exceeds u32")?;
        self.arch_blob[written..].fill(0);
        self.pad = 0;
        Ok(())
    }
}
