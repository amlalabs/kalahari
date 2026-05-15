// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` architecture constants for interrupt routing.

/// Base GSI number for virtio device IRQs on `x86_64`.
///
/// IRQs 0-15 are reserved for legacy ISA devices (PIC).
/// Virtio devices start at GSI 5 to avoid conflicts with
/// common legacy IRQs (timer=0, keyboard=1, cascade=2, COM1=4).
pub const VIRTIO_IRQ_BASE: u32 = 5;
