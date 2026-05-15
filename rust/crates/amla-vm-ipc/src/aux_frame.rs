// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Shared aux-transport frame encoding.
//!
//! Both Unix transports use the same byte payload:
//! `[seq: u32 LE][count: u32 LE][meta_0: u64 LE]...[meta_N: u64 LE]`.

use std::io;

const HEADER_LEN: usize = 8;
const META_LEN: usize = 8;

pub(crate) fn encode(
    seq: u32,
    metas: impl IntoIterator<Item = u64, IntoIter: ExactSizeIterator>,
) -> io::Result<Vec<u8>> {
    let metas = metas.into_iter();
    let count = metas.len();
    let count_u32 = u32::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "aux: too many resource slots"))?;
    let capacity = frame_len(count)?;
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(&seq.to_le_bytes());
    payload.extend_from_slice(&count_u32.to_le_bytes());
    for meta in metas {
        payload.extend_from_slice(&meta.to_le_bytes());
    }
    Ok(payload)
}

pub(crate) fn decode(
    expected_seq: u32,
    expected_count: usize,
    data: &[u8],
) -> io::Result<Vec<u64>> {
    if data.len() < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "aux: data too short for header",
        ));
    }

    let seq = read_u32(data, 0)?;
    let count = usize::try_from(read_u32(data, 4)?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "aux: slot count overflows usize",
        )
    })?;
    if seq != expected_seq || count != expected_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "aux: seq/count does not match ring frame",
        ));
    }

    let expected_len = frame_len(count)?;
    if data.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "aux: count/meta length mismatch",
        ));
    }

    let mut metas = Vec::with_capacity(count);
    for chunk in data[HEADER_LEN..].chunks_exact(META_LEN) {
        metas.push(u64::from_le_bytes(chunk.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "aux: truncated metadata")
        })?));
    }
    Ok(metas)
}

fn frame_len(count: usize) -> io::Result<usize> {
    count
        .checked_mul(META_LEN)
        .and_then(|metas| HEADER_LEN.checked_add(metas))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "aux: frame length overflows"))
}

fn read_u32(data: &[u8], offset: usize) -> io::Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "aux: truncated u32"))?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "aux: invalid u32")
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aux_frame_round_trips_metadata() {
        let payload = encode(7, [10, 20, 30]).unwrap();
        assert_eq!(decode(7, 3, &payload).unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn aux_frame_rejects_mismatched_count() {
        let payload = encode(7, [10, 20]).unwrap();
        assert!(decode(7, 3, &payload).is_err());
    }

    #[test]
    fn aux_frame_rejects_trailing_bytes() {
        let mut payload = encode(7, [10]).unwrap();
        payload.push(0);
        assert!(decode(7, 1, &payload).is_err());
    }
}
