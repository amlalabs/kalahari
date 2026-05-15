// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Resource slot helpers for IPC encode/decode.

/// Resource slots being decoded for one IPC message.
///
/// Generated `IpcMessage` impls use this to enforce that every supplied
/// kernel resource is consumed exactly once by the message wire payload.
#[cfg(unix)]
pub struct ResourceSlots {
    slots: Vec<Option<crate::AuxSlot>>,
    remaining: usize,
}

#[cfg(unix)]
impl ResourceSlots {
    /// Create a decoder from the slots delivered with the current frame.
    pub fn new(slots: Vec<crate::AuxSlot>) -> Self {
        Self {
            remaining: slots.len(),
            slots: slots.into_iter().map(Some).collect(),
        }
    }

    /// Take one slot by wire index.
    ///
    /// Returns `MissingResource` when the index is out of range or when the
    /// same index is referenced more than once.
    pub fn take(&mut self, index: u32) -> crate::Result<crate::AuxSlot> {
        let index_usize = usize::try_from(index)
            .map_err(|_| crate::Error::Protocol("resource slot index overflows usize"))?;
        let slot = self
            .slots
            .get_mut(index_usize)
            .and_then(Option::take)
            .ok_or(crate::Error::MissingResource(index))?;
        self.remaining -= 1;
        Ok(slot)
    }

    /// Finish decoding and reject any slots that were delivered but unused.
    pub fn finish_no_unused(self) -> crate::Result<()> {
        if self.remaining == 0 {
            return Ok(());
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_some)
            .ok_or(crate::Error::Protocol("resource slot accounting mismatch"))?;
        let index = u32::try_from(index)
            .map_err(|_| crate::Error::Protocol("resource slot index overflows u32"))?;
        Err(crate::Error::UnusedResource(index))
    }
}

/// Take a slot from a decoder by index.
///
/// Used by generated `deserialize` code. Each slot can only be taken once;
/// subsequent takes at the same index return `MissingResource`.
#[cfg(unix)]
pub fn take_slot(slots: &mut ResourceSlots, index: u32) -> crate::Result<crate::AuxSlot> {
    slots.take(index)
}
