// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Timeout configuration for the TLS MITM pipeline.

use std::time::Duration;

const DEFAULT_CLIENT_HELLO: Duration = Duration::from_secs(5);
const DEFAULT_GUEST_TLS_HANDSHAKE: Duration = Duration::from_secs(10);
const DEFAULT_UPSTREAM_CONNECT: Duration = Duration::from_secs(10);
const DEFAULT_UPSTREAM_TLS_HANDSHAKE: Duration = Duration::from_secs(10);
const DEFAULT_UPSTREAM_HTTP_HANDSHAKE: Duration = Duration::from_secs(10);
const DEFAULT_UPSTREAM_RESPONSE_HEADERS: Duration = Duration::from_mins(1);

/// Per-stage deadlines for the TLS MITM connection path.
///
/// All values must be non-zero. Timeouts are fail-closed: the proxy closes
/// the guest-side connection or returns a synthesized gateway error instead
/// of continuing with a partially initialized upstream path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MitmTimeouts {
    client_hello: Duration,
    guest_tls_handshake: Duration,
    upstream_connect: Duration,
    upstream_tls_handshake: Duration,
    upstream_http_handshake: Duration,
    upstream_response_headers: Duration,
}

impl Default for MitmTimeouts {
    fn default() -> Self {
        Self {
            client_hello: DEFAULT_CLIENT_HELLO,
            guest_tls_handshake: DEFAULT_GUEST_TLS_HANDSHAKE,
            upstream_connect: DEFAULT_UPSTREAM_CONNECT,
            upstream_tls_handshake: DEFAULT_UPSTREAM_TLS_HANDSHAKE,
            upstream_http_handshake: DEFAULT_UPSTREAM_HTTP_HANDSHAKE,
            upstream_response_headers: DEFAULT_UPSTREAM_RESPONSE_HEADERS,
        }
    }
}

impl MitmTimeouts {
    /// Deadline for reading a complete guest `ClientHello`.
    #[must_use]
    pub const fn client_hello(self) -> Duration {
        self.client_hello
    }

    /// Deadline for the guest-facing TLS handshake after SNI policy passes.
    #[must_use]
    pub const fn guest_tls_handshake(self) -> Duration {
        self.guest_tls_handshake
    }

    /// Deadline for opening the host TCP stream.
    #[must_use]
    pub const fn upstream_connect(self) -> Duration {
        self.upstream_connect
    }

    /// Deadline for the host-facing TLS handshake.
    #[must_use]
    pub const fn upstream_tls_handshake(self) -> Duration {
        self.upstream_tls_handshake
    }

    /// Deadline for the host-facing hyper client handshake.
    #[must_use]
    pub const fn upstream_http_handshake(self) -> Duration {
        self.upstream_http_handshake
    }

    /// Deadline for receiving upstream response headers after request dispatch.
    #[must_use]
    pub const fn upstream_response_headers(self) -> Duration {
        self.upstream_response_headers
    }

    /// Return a copy with a different `ClientHello` deadline.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMitmTimeout`] when `timeout` is zero.
    pub fn with_client_hello(self, timeout: Duration) -> Result<Self, InvalidMitmTimeout> {
        Ok(Self {
            client_hello: checked("client_hello", timeout)?,
            ..self
        })
    }

    /// Return a copy with a different guest TLS handshake deadline.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMitmTimeout`] when `timeout` is zero.
    pub fn with_guest_tls_handshake(self, timeout: Duration) -> Result<Self, InvalidMitmTimeout> {
        Ok(Self {
            guest_tls_handshake: checked("guest_tls_handshake", timeout)?,
            ..self
        })
    }

    /// Return a copy with a different upstream TCP connect deadline.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMitmTimeout`] when `timeout` is zero.
    pub fn with_upstream_connect(self, timeout: Duration) -> Result<Self, InvalidMitmTimeout> {
        Ok(Self {
            upstream_connect: checked("upstream_connect", timeout)?,
            ..self
        })
    }

    /// Return a copy with a different upstream TLS handshake deadline.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMitmTimeout`] when `timeout` is zero.
    pub fn with_upstream_tls_handshake(
        self,
        timeout: Duration,
    ) -> Result<Self, InvalidMitmTimeout> {
        Ok(Self {
            upstream_tls_handshake: checked("upstream_tls_handshake", timeout)?,
            ..self
        })
    }

    /// Return a copy with a different upstream hyper handshake deadline.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMitmTimeout`] when `timeout` is zero.
    pub fn with_upstream_http_handshake(
        self,
        timeout: Duration,
    ) -> Result<Self, InvalidMitmTimeout> {
        Ok(Self {
            upstream_http_handshake: checked("upstream_http_handshake", timeout)?,
            ..self
        })
    }

    /// Return a copy with a different upstream response-header deadline.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMitmTimeout`] when `timeout` is zero.
    pub fn with_upstream_response_headers(
        self,
        timeout: Duration,
    ) -> Result<Self, InvalidMitmTimeout> {
        Ok(Self {
            upstream_response_headers: checked("upstream_response_headers", timeout)?,
            ..self
        })
    }
}

/// Invalid timeout configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{field} timeout must be non-zero")]
pub struct InvalidMitmTimeout {
    field: &'static str,
}

const fn checked(field: &'static str, timeout: Duration) -> Result<Duration, InvalidMitmTimeout> {
    if timeout.is_zero() {
        Err(InvalidMitmTimeout { field })
    } else {
        Ok(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_timeout() {
        assert!(
            MitmTimeouts::default()
                .with_client_hello(Duration::ZERO)
                .is_err()
        );
    }

    #[test]
    fn updates_one_timeout_without_changing_others() {
        let original = MitmTimeouts::default();
        let updated = original
            .with_upstream_connect(Duration::from_millis(25))
            .unwrap();
        assert_eq!(updated.upstream_connect(), Duration::from_millis(25));
        assert_eq!(updated.client_hello(), original.client_hello());
        assert_eq!(
            updated.upstream_http_handshake(),
            original.upstream_http_handshake(),
        );
    }
}
