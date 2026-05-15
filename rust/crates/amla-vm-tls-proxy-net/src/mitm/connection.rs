// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! [`TlsMitmInterceptor`] policy adapter for the owned-stream API.
//!
//! The interceptor receives an owned guest TCP stream and a deferred
//! [`HostConnector`]. TLS peeking runs before the connector is consumed:
//! malformed streams fail closed without opening a host socket. SNI
//! host-policy mismatches also fail closed without opening a host socket.

use std::sync::Arc;

use amla_interceptor::{
    BoxFuture, HostConnector, LocalSocket, TcpConnectionPolicy, TcpFlow, TcpOpenAction,
    TrustedTcpInterceptor,
};

use crate::MitmTimeouts;
use crate::ca::CertificateAuthority;
use crate::handler::HttpMitmHandler;
use crate::mitm::task::run_proxy_owned;
use crate::policy::MitmPolicy;

/// Policy and trusted-interceptor adapter for TLS MITM.
///
/// Generic over `H: HttpMitmHandler` — monomorphized, no `dyn` dispatch on
/// handler methods. Callers typically own a single concrete handler type per
/// application; stashing it as `Arc<H>` (rather than `Arc<dyn …>`) saves a
/// vtable lookup per callback + a heap allocation per method call.
pub struct TlsMitmInterceptor<H: HttpMitmHandler> {
    ca: Arc<CertificateAuthority>,
    policy: MitmPolicy,
    handler: Arc<H>,
    host_tls_config: Arc<rustls::ClientConfig>,
    timeouts: MitmTimeouts,
}

impl<H: HttpMitmHandler> Clone for TlsMitmInterceptor<H> {
    fn clone(&self) -> Self {
        Self {
            ca: Arc::clone(&self.ca),
            policy: self.policy.clone(),
            handler: Arc::clone(&self.handler),
            host_tls_config: Arc::clone(&self.host_tls_config),
            timeouts: self.timeouts,
        }
    }
}

impl<H: HttpMitmHandler> TlsMitmInterceptor<H> {
    /// Create an interceptor that uses the platform default trust roots for
    /// the host-facing TLS session. Call [`crate::install_crypto_provider`]
    /// before this if your application has multiple rustls providers in the
    /// feature graph (most do not).
    pub fn new(ca: Arc<CertificateAuthority>, policy: MitmPolicy, handler: Arc<H>) -> Self {
        let mut host_tls_config = default_host_tls_config();
        apply_host_alpn(&mut host_tls_config);
        Self {
            ca,
            policy,
            handler,
            host_tls_config: Arc::new(host_tls_config),
            timeouts: MitmTimeouts::default(),
        }
    }

    /// Create an interceptor with caller-supplied timeout settings.
    pub fn with_timeouts(
        ca: Arc<CertificateAuthority>,
        policy: MitmPolicy,
        handler: Arc<H>,
        timeouts: MitmTimeouts,
    ) -> Self {
        let mut host_tls_config = default_host_tls_config();
        apply_host_alpn(&mut host_tls_config);
        Self {
            ca,
            policy,
            handler,
            host_tls_config: Arc::new(host_tls_config),
            timeouts,
        }
    }

    /// Create with a caller-supplied host-facing TLS config — useful for
    /// tests that pin a custom trust store, or for production deployments
    /// that want specific cipher suites on the host leg.
    ///
    /// The MITM overwrites `alpn_protocols` on the supplied config: ALPN is
    /// an internal MITM concern (must match what we advertise to the guest
    /// so the two legs' negotiated protocols can line up). Callers with
    /// strong opinions about on-wire protocol would short-circuit cross-
    /// protocol translation anyway.
    pub fn with_host_tls_config(
        ca: Arc<CertificateAuthority>,
        policy: MitmPolicy,
        handler: Arc<H>,
        mut host_tls_config: rustls::ClientConfig,
    ) -> Self {
        apply_host_alpn(&mut host_tls_config);
        Self {
            ca,
            policy,
            handler,
            host_tls_config: Arc::new(host_tls_config),
            timeouts: MitmTimeouts::default(),
        }
    }

    /// Create with caller-supplied host-facing TLS config and timeouts.
    ///
    /// The MITM overwrites `alpn_protocols` on the supplied config for the
    /// same reason as [`Self::with_host_tls_config`].
    pub fn with_host_tls_config_and_timeouts(
        ca: Arc<CertificateAuthority>,
        policy: MitmPolicy,
        handler: Arc<H>,
        mut host_tls_config: rustls::ClientConfig,
        timeouts: MitmTimeouts,
    ) -> Self {
        apply_host_alpn(&mut host_tls_config);
        Self {
            ca,
            policy,
            handler,
            host_tls_config: Arc::new(host_tls_config),
            timeouts,
        }
    }
}

/// Set the host-leg ALPN offer list to match what we advertise guest-side:
/// h2 first, h1 fallback. Kept in one function so the two constructors
/// can't drift. Warns if the caller pre-set an ALPN list that differs —
/// silent clobbering has bitten test authors porting configs between
/// releases.
fn apply_host_alpn(cfg: &mut rustls::ClientConfig) {
    let expected: Vec<Vec<u8>> = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if !cfg.alpn_protocols.is_empty() && cfg.alpn_protocols != expected {
        log::warn!(
            "TlsMitmInterceptor::with_host_tls_config: overriding caller's \
             alpn_protocols={:?} with the MITM's fixed list {:?}",
            cfg.alpn_protocols
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>(),
            ["h2", "http/1.1"],
        );
    }
    cfg.alpn_protocols = expected;
}

impl<H: HttpMitmHandler> TcpConnectionPolicy for TlsMitmInterceptor<H> {
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        if self.policy.should_intercept_addr(flow.remote_addr) {
            TcpOpenAction::Intercept(Box::new((*self).clone()))
        } else {
            TcpOpenAction::NoOpinion
        }
    }
}

impl<H: HttpMitmHandler> TrustedTcpInterceptor for TlsMitmInterceptor<H> {
    fn run(
        self: Box<Self>,
        guest: LocalSocket,
        flow: TcpFlow,
        connector: HostConnector,
    ) -> BoxFuture<'static, ()> {
        Box::pin(run_proxy_owned(
            guest,
            flow,
            connector,
            Arc::clone(&self.ca),
            self.policy.clone(),
            Arc::clone(&self.handler),
            Arc::clone(&self.host_tls_config),
            self.timeouts,
        ))
    }
}

/// Default host-facing TLS config using webpki-roots for trust. ALPN is
/// intentionally unset here — the constructor path calls [`apply_host_alpn`]
/// to install the canonical `[h2, http/1.1]` offer, so ALPN stays a single
/// source of truth regardless of which constructor ran.
fn default_host_tls_config() -> rustls::ClientConfig {
    crate::install_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
