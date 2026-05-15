// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Fatal TLS alert records, emitted directly to the guest when the MITM
//! can't proceed far enough to hand the stream to `TlsAcceptor`.
//!
//! Once `TlsAcceptor::accept` is running, rustls produces its own alerts
//! through the normal handshake failure paths. Before that — specifically,
//! if [`crate::peek::peek_sni`] fails — we're still in raw-bytes territory
//! and must hand-craft a record. These bytes match the TLS 1.2 record-layer
//! wire format (TLS 1.3 uses the same on the guest-facing leg because the
//! server's version is chosen during the handshake we never start).
//!
//! Record layout: `[type(1), version(2), length(2), level(1), description(1)]`
//! where `type = 0x15` (Alert), `version = 0x0303` (TLS 1.2), `length = 0x0002`.

use crate::peek::PeekError;

/// Alert content type.
const ALERT: u8 = 0x15;
/// TLS 1.2 legacy record version.
const TLS_1_2: [u8; 2] = [0x03, 0x03];
/// Record length: always 2 bytes (level + description).
const ALERT_LEN: [u8; 2] = [0x00, 0x02];
/// Fatal severity.
const FATAL: u8 = 0x02;

// Alert descriptions — RFC 5246 §7.2.2 / RFC 8446 §6.2. Only the three we
// actually emit today are defined; `protocol_version(70)` and
// `internal_error(80)` will be added back when they have real callers.
const DESC_UNEXPECTED_MESSAGE: u8 = 10;
const DESC_HANDSHAKE_FAILURE: u8 = 40;
const DESC_UNRECOGNIZED_NAME: u8 = 112;

/// Build a 7-byte fatal alert record.
const fn record(description: u8) -> [u8; 7] {
    [
        ALERT,
        TLS_1_2[0],
        TLS_1_2[1],
        ALERT_LEN[0],
        ALERT_LEN[1],
        FATAL,
        description,
    ]
}

// `static` (not `const`) so callers can take a `'static` reference suitable
// for `bytes::Bytes::from_static` — const items have no stable address.
pub static FATAL_HANDSHAKE_FAILURE: [u8; 7] = record(DESC_HANDSHAKE_FAILURE);
pub static FATAL_UNRECOGNIZED_NAME: [u8; 7] = record(DESC_UNRECOGNIZED_NAME);
pub static FATAL_UNEXPECTED_MESSAGE: [u8; 7] = record(DESC_UNEXPECTED_MESSAGE);

/// Map a peek failure to the most informative fatal alert.
///
/// `MissingSni` → `unrecognized_name(112)` — the spec-defined response to a
/// server that can't identify the requested virtual host.
///
/// `NotClientHello` → `unexpected_message(10)` — the record-layer framing
/// expected a handshake but got something else.
///
/// `Oversized` / `Malformed` / `Io` / `Eof` / `Ech` / `TimedOut` →
/// `handshake_failure(40)` — generic "I can't proceed", which is what the
/// guest should see so it doesn't retry without addressing the upstream cause.
#[must_use]
pub fn for_peek_error(e: &PeekError) -> &'static [u8] {
    match e {
        PeekError::MissingSni => &FATAL_UNRECOGNIZED_NAME,
        PeekError::NotClientHello => &FATAL_UNEXPECTED_MESSAGE,
        PeekError::Oversized
        | PeekError::Malformed(_)
        | PeekError::Io(_)
        | PeekError::Eof
        | PeekError::Ech
        | PeekError::TimedOut(_) => &FATAL_HANDSHAKE_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn fatal_records_have_correct_wire_format() {
        // Every alert: [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, desc]
        for r in [
            FATAL_HANDSHAKE_FAILURE,
            FATAL_UNRECOGNIZED_NAME,
            FATAL_UNEXPECTED_MESSAGE,
        ] {
            assert_eq!(r[0], ALERT, "content type must be Alert (0x15)");
            assert_eq!(&r[1..3], &TLS_1_2, "record version must be TLS 1.2");
            assert_eq!(&r[3..5], &ALERT_LEN, "declared length must be 2");
            assert_eq!(r[5], FATAL, "level must be fatal");
        }
        assert_eq!(FATAL_HANDSHAKE_FAILURE[6], DESC_HANDSHAKE_FAILURE);
        assert_eq!(FATAL_UNRECOGNIZED_NAME[6], DESC_UNRECOGNIZED_NAME);
        assert_eq!(FATAL_UNEXPECTED_MESSAGE[6], DESC_UNEXPECTED_MESSAGE);
    }

    #[test]
    fn for_peek_error_maps_missing_sni_to_unrecognized_name() {
        assert_eq!(
            for_peek_error(&PeekError::MissingSni),
            &FATAL_UNRECOGNIZED_NAME[..],
        );
    }

    #[test]
    fn for_peek_error_maps_not_client_hello_to_unexpected_message() {
        assert_eq!(
            for_peek_error(&PeekError::NotClientHello),
            &FATAL_UNEXPECTED_MESSAGE[..],
        );
    }

    #[test]
    fn for_peek_error_maps_misc_to_handshake_failure() {
        assert_eq!(
            for_peek_error(&PeekError::Oversized),
            &FATAL_HANDSHAKE_FAILURE[..],
        );
        assert_eq!(
            for_peek_error(&PeekError::Ech),
            &FATAL_HANDSHAKE_FAILURE[..],
        );
        assert_eq!(
            for_peek_error(&PeekError::Eof),
            &FATAL_HANDSHAKE_FAILURE[..],
        );
        assert_eq!(
            for_peek_error(&PeekError::Malformed("bad length".into())),
            &FATAL_HANDSHAKE_FAILURE[..],
        );
        assert_eq!(
            for_peek_error(&PeekError::Io(io::Error::other("oh no"))),
            &FATAL_HANDSHAKE_FAILURE[..],
        );
        assert_eq!(
            for_peek_error(&PeekError::TimedOut(std::time::Duration::from_secs(1))),
            &FATAL_HANDSHAKE_FAILURE[..],
        );
    }
}
