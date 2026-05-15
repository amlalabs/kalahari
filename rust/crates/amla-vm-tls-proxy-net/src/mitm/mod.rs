// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Async MITM pipeline.
//!
//! Submodules:
//! - [`alert`]: hand-rolled fatal TLS alert records for pre-handshake
//!   failures (missing SNI, oversized `ClientHello`, etc.).
//! - [`body`]: streaming per-frame async tap around `http_body::Body`.
//! - [`upstream`]: per-connection actor owning the host-facing
//!   `SendRequest` (h1 or h2).
//! - [`service`]: hyper `service_fn` that drives a single request/response
//!   exchange through the [`crate::handler::HttpMitmHandler`].
//! - [`task`]: orchestrates a single MITM connection — peek, TLS handshakes,
//!   hyper server/client, and owned stream routing.
//! - [`connection`]: `TlsMitmInterceptor` policy adapter.
//! - [`xlate`]: RFC 7540 §8.1.2 cross-protocol (h1 ↔ h2) header/URI hygiene,
//!   applied when guest and host negotiated different HTTP versions.

pub mod alert;
pub mod body;
pub mod connection;
pub mod service;
pub mod task;
pub mod upstream;
pub mod xlate;

pub use connection::TlsMitmInterceptor;
