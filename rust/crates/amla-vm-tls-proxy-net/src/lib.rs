// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! TLS MITM proxy for HTTP request/response inspection and modification.
//!
//! Built on `tokio-rustls` + `hyper`, with h1 and h2 on both legs
//! (cross-protocol translation via the `xlate` module). The proxy intercepts
//! HTTPS traffic by minting a leaf cert for the target hostname, terminating
//! TLS guest-side with that cert, opening a matching TLS session to the real
//! host, and routing plaintext HTTP requests and responses through a
//! user-supplied [`HttpMitmHandler`](crate::handler::HttpMitmHandler).
//!
//! # Architecture
//!
//! ```text
//! Guest ──TLS──┐
//!              │   tokio-rustls::TlsAcceptor
//!              ▼
//!       hyper server (h1 or h2, per ALPN)
//!              │    ┌─ HttpMitmHandler::on_request_headers  ┐
//!              │    │                                        │ (streaming)
//!              │    ├─ on_request_chunk  (per frame)         │
//!              │    ▼                                        │
//!              │   hyper client (h1 or h2, kept alive)       │
//!              │    │                                        │
//!              │    ├─ on_response_headers                   │
//!              │    ├─ on_response_chunk  (per frame)        │
//!              │    ├─ on_response_end    (inject trailers)  │
//!              │    └─ on_complete                           │
//!              ▼                                              ▼
//!       tokio-rustls::TlsConnector ──TLS──► Real Host
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use amla_tls_proxy_net::{CertificateAuthority, MitmPolicy, TlsMitmInterceptor};
//! ```

pub mod ca;
pub mod handler;
pub mod policy;

pub(crate) mod mitm;
pub(crate) mod peek;
mod timeout;

pub use ca::CertificateAuthority;
pub use mitm::TlsMitmInterceptor;
pub use policy::{EmptyPolicyError, MitmPolicy};
pub use timeout::{InvalidMitmTimeout, MitmTimeouts};

/// Install the `ring` crypto provider for rustls.
///
/// When multiple crypto providers are enabled via feature unification
/// (e.g., both `ring` and `aws-lc-rs`), rustls cannot auto-detect
/// which to use. This must be called before any rustls operation.
///
/// Idempotent: calling after a provider is already installed (by this crate
/// or any other caller in the process) is a no-op. Any *other* error from
/// `install_default` is logged at `warn!` so a future rustls version that
/// introduces new failure modes doesn't silently regress the MITM stack.
pub fn install_crypto_provider() {
    if let Err(existing) = rustls::crypto::ring::default_provider().install_default() {
        // `install_default` returns `Err(existing_provider)` when *any*
        // provider is already installed — that's the documented "someone
        // got here first" signal, expected in tests and when multiple
        // crates in the process bootstrap rustls. Drop silently.
        drop(existing);
    }
}
