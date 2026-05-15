// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Host-facing hyper client handshake + sender adapter.
//!
//! Exposes [`handshake`], which performs an h1 or h2 client handshake and
//! returns a ([`UpstreamSender`], connection future) pair. The connection
//! future is not spawned — the caller joins it with the guest-facing
//! `serve_connection` future inside `run_proxy`, keeping the whole MITM
//! connection on a single task.
//!
//! [`UpstreamSender`] is `Clone` for both h1 and h2 so each `service_fn`
//! invocation can cheaply clone it and call [`UpstreamSender::send_request`]
//! directly.
//!
//! ## h1 vs h2 dispatch
//!
//! hyper's `hyper::client::conn::http1::SendRequest` is **not** `Clone` — h1
//! serializes requests on its single wire, so concurrent callers must
//! synchronize. We wrap the h1 sender in `Arc<tokio::sync::Mutex<_>>`: each
//! service call briefly locks, calls `send_request` (which synchronously
//! enqueues onto the connection task and returns a `ResponseFuture`), drops
//! the guard, and then awaits the response outside the lock. The mutex is
//! held for microseconds — no `.await` inside the critical section.
//!
//! hyper's h2 `SendRequest` **is** `Clone`, and h2 multiplexes concurrent
//! streams natively. The h2 path carries a plain (cloneable) `SendRequest`
//! with no mutex, and returns hyper's concrete `ResponseFuture` directly —
//! no boxing, no type erasure.

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use amla_interceptor::HostConnector;

use crate::MitmTimeouts;

/// Body type used for upstream requests. Service layer boxes the tapped
/// guest body into this before dispatch. `UnsyncBoxBody` is used (not
/// `BoxBody`) because `TappedBody`'s internal `BoxFuture` is `Send` but not
/// `Sync`, and hyper's client doesn't require `Sync` on the body.
pub type UpstreamBody = UnsyncBoxBody<Bytes, hyper::Error>;

/// Which HTTP version to speak on the host leg.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
}

/// Inner variant — different wiring per protocol.
///
/// h1 pays for a mutex because `SendRequest<B>` isn't `Clone`; h2 pays
/// nothing because its sender already `Clone`s and multiplexes. Using an
/// enum (rather than a trait object) keeps the dispatch monomorphized and
/// inlineable.
#[derive(Clone)]
enum Inner {
    Http1(Arc<Mutex<hyper::client::conn::http1::SendRequest<UpstreamBody>>>),
    Http2(hyper::client::conn::http2::SendRequest<UpstreamBody>),
}

/// Cloneable send handle for the host-facing hyper client.
///
/// Each `service_fn` invocation clones this and calls
/// [`send_request`][Self::send_request]. Concurrency:
///
/// - **h1**: requests serialize on the wire; the per-sender `Mutex` gates
///   the (non-`await`ing) enqueue step and is released before the response
///   is awaited.
/// - **h2**: requests multiplex; no synchronization — each clone of the
///   inner `SendRequest` submits on the shared connection independently.
#[derive(Clone)]
pub struct UpstreamSender {
    inner: Inner,
}

impl UpstreamSender {
    /// Dispatch a request and await the response.
    ///
    /// On the h1 branch the mutex is held only for the duration of the
    /// synchronous `send_request` call — the returned `ResponseFuture` is
    /// bound to a `let` so the `MutexGuard` drops at the end of the inner
    /// block, then awaited outside the lock. (hyper's h1
    /// `SendRequest::send_request` doesn't borrow from `&mut self` once the
    /// future is constructed, so the guard lifetime can end safely.)
    ///
    /// On the h2 branch the sender is simply cloned and the returned
    /// future is awaited directly — no lock, no type erasure.
    pub(crate) async fn send_request(
        &self,
        req: http::Request<UpstreamBody>,
    ) -> Result<http::Response<Incoming>, hyper::Error> {
        match &self.inner {
            Inner::Http1(mutex) => {
                let fut = {
                    let mut guard = mutex.lock().await;
                    guard.send_request(req)
                };
                fut.await
            }
            Inner::Http2(sender) => {
                let mut sender = sender.clone();
                sender.send_request(req).await
            }
        }
    }
}

/// Cloneable upstream handle used by the service layer.
///
/// Tests can pass a ready hyper sender. The owned-stream runner passes the
/// lazy variant so request-header `Block` decisions happen before any origin
/// socket is opened.
#[derive(Clone)]
pub enum UpstreamEndpoint {
    #[cfg(test)]
    Ready {
        sender: UpstreamSender,
        protocol: Protocol,
    },
    Lazy(LazyUpstream),
}

impl UpstreamEndpoint {
    #[cfg(test)]
    pub(crate) const fn ready(sender: UpstreamSender, protocol: Protocol) -> Self {
        Self::Ready { sender, protocol }
    }

    pub(crate) const fn lazy(lazy: LazyUpstream) -> Self {
        Self::Lazy(lazy)
    }

    pub(crate) async fn sender_and_protocol(
        &self,
    ) -> Result<(UpstreamSender, Protocol), UpstreamInitError> {
        match self {
            #[cfg(test)]
            Self::Ready { sender, protocol } => Ok((sender.clone(), *protocol)),
            Self::Lazy(lazy) => lazy.sender_and_protocol().await,
        }
    }
}

/// Lazily opens, TLS-handshakes, and hyper-handshakes the host leg.
#[derive(Clone)]
pub struct LazyUpstream {
    inner: Arc<Mutex<LazyState>>,
}

struct LazyState {
    init: Option<LazyInit>,
    ready: Option<(UpstreamSender, Protocol)>,
}

struct LazyInit {
    connector: HostConnector,
    server_name: ServerName<'static>,
    hostname: String,
    host_tls_config: Arc<rustls::ClientConfig>,
    timeouts: MitmTimeouts,
}

impl LazyUpstream {
    pub(crate) fn new(
        connector: HostConnector,
        server_name: ServerName<'static>,
        hostname: String,
        host_tls_config: Arc<rustls::ClientConfig>,
        timeouts: MitmTimeouts,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LazyState {
                init: Some(LazyInit {
                    connector,
                    server_name,
                    hostname,
                    host_tls_config,
                    timeouts,
                }),
                ready: None,
            })),
        }
    }

    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn sender_and_protocol(&self) -> Result<(UpstreamSender, Protocol), UpstreamInitError> {
        let mut state = self.inner.lock().await;
        if let Some((sender, protocol)) = &state.ready {
            return Ok((sender.clone(), *protocol));
        }

        let Some(init) = state.init.take() else {
            return Err(UpstreamInitError::Unavailable);
        };

        let host_stream =
            match timeout(init.timeouts.upstream_connect(), init.connector.connect()).await {
                Ok(result) => result.map_err(UpstreamInitError::Connect)?,
                Err(_) => {
                    return Err(UpstreamInitError::TimedOut {
                        stage: UpstreamInitStage::Connect,
                        timeout: init.timeouts.upstream_connect(),
                    });
                }
            };
        let host_tls_fut =
            TlsConnector::from(init.host_tls_config).connect(init.server_name, host_stream);
        let host_tls = match timeout(init.timeouts.upstream_tls_handshake(), host_tls_fut).await {
            Ok(result) => result.map_err(UpstreamInitError::Tls)?,
            Err(_) => {
                return Err(UpstreamInitError::TimedOut {
                    stage: UpstreamInitStage::TlsHandshake,
                    timeout: init.timeouts.upstream_tls_handshake(),
                });
            }
        };
        let host_proto = negotiated_protocol(host_tls.get_ref().1.alpn_protocol())
            .map_err(UpstreamInitError::UnsupportedAlpn)?;
        let (sender, conn) = match timeout(
            init.timeouts.upstream_http_handshake(),
            handshake(host_tls, host_proto),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(UpstreamInitError::TimedOut {
                    stage: UpstreamInitStage::HttpHandshake,
                    timeout: init.timeouts.upstream_http_handshake(),
                });
            }
        };
        tokio::spawn(async move {
            conn.await;
            log::trace!("lazy upstream connection driver finished");
        });

        log::trace!(
            "lazy upstream initialized for {:?}: proto={host_proto:?}",
            init.hostname
        );
        state.ready = Some((sender.clone(), host_proto));
        Ok((sender, host_proto))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamInitError {
    #[error("host connect failed: {0}")]
    Connect(#[source] io::Error),
    #[error("host TLS handshake failed: {0}")]
    Tls(#[source] io::Error),
    #[error("host chose unsupported ALPN: {0:?}")]
    UnsupportedAlpn(Vec<u8>),
    #[error("upstream HTTP handshake failed: {0}")]
    Http(#[from] hyper::Error),
    #[error("upstream {stage:?} timed out after {timeout:?}")]
    TimedOut {
        stage: UpstreamInitStage,
        timeout: Duration,
    },
    #[error("upstream initialization unavailable after a previous failure")]
    Unavailable,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UpstreamInitStage {
    Connect,
    TlsHandshake,
    HttpHandshake,
}

impl UpstreamInitError {
    pub(crate) const fn guest_status(&self) -> http::StatusCode {
        match self {
            Self::TimedOut { .. } => http::StatusCode::GATEWAY_TIMEOUT,
            Self::Connect(_)
            | Self::Tls(_)
            | Self::UnsupportedAlpn(_)
            | Self::Http(_)
            | Self::Unavailable => http::StatusCode::BAD_GATEWAY,
        }
    }
}

/// Map a negotiated ALPN byte-string to our [`Protocol`] enum.
pub fn negotiated_protocol(alpn: Option<&[u8]>) -> Result<Protocol, Vec<u8>> {
    match alpn {
        Some(b"h2") => Ok(Protocol::Http2),
        Some(b"http/1.1") | None => Ok(Protocol::Http1),
        Some(other) => Err(other.to_vec()),
    }
}

/// Type-erased connection-driver future. The caller (`run_proxy`) joins
/// this with the guest-facing `serve_connection` so both run concurrently
/// on the same task.
///
/// The erasure here is load-bearing: h1 and h2 return distinct unnameable
/// connection future types, and `handshake` needs a single return type.
/// The boxing is per-*connection* (not per-request) — one alloc across the
/// full MITM session lifetime.
pub type ConnFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Perform the host-facing handshake and return `(sender, conn_future)`.
///
/// The returned future drives the hyper connection; hyper's h1 and h2
/// connection types both expose a single `await`-able future that resolves
/// when the connection ends. Caller must poll it (e.g. via `tokio::join!`)
/// for data to flow on concurrent response bodies.
pub async fn handshake<S>(
    host_tls: S,
    protocol: Protocol,
) -> Result<(UpstreamSender, ConnFuture), hyper::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(host_tls);
    let (inner, fut): (Inner, ConnFuture) = match protocol {
        Protocol::Http1 => {
            let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            let fut: ConnFuture = Box::pin(async move {
                match conn.await {
                    Ok(()) => log::trace!("upstream h1 connection closed cleanly"),
                    Err(e) => log::debug!("upstream h1 connection ended: {e:#}"),
                }
            });
            (Inner::Http1(Arc::new(Mutex::new(sender))), fut)
        }
        Protocol::Http2 => {
            let (sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
            let fut: ConnFuture = Box::pin(async move {
                match conn.await {
                    Ok(()) => log::debug!("upstream h2 connection closed cleanly"),
                    Err(e) => log::warn!("upstream h2 connection error: {e:#}"),
                }
            });
            (Inner::Http2(sender), fut)
        }
    };
    Ok((UpstreamSender { inner }, fut))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::service::service_fn;
    use std::convert::Infallible;

    /// Spin up a hyper h1 server on one end of a `tokio::io::duplex` pair
    /// and return the other end for clients to connect to. `service`
    /// handles each incoming request.
    fn spawn_test_upstream<F, Fut>(service: F) -> tokio::io::DuplexStream
    where
        F: Fn(http::Request<Incoming>) -> Fut + Send + Sync + 'static + Clone,
        Fut: std::future::Future<
                Output = Result<http::Response<UnsyncBoxBody<Bytes, Infallible>>, Infallible>,
            > + Send,
    {
        let (client_side, server_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let svc = service_fn(service);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_side), svc)
                .await
            {
                log::debug!("test spawn_test_upstream serve_connection ended: {e}");
            }
        });
        client_side
    }

    /// Drive a sender's `send_request` concurrently with the returned conn
    /// future. The caller joins both — this helper does it for the test.
    async fn round_trip(
        sender: UpstreamSender,
        conn: ConnFuture,
        req: http::Request<UpstreamBody>,
    ) -> Result<http::Response<Incoming>, hyper::Error> {
        tokio::select! {
            resp = sender.send_request(req) => resp,
            () = conn => panic!("conn resolved before response"),
        }
    }

    #[tokio::test]
    async fn h1_handshake_roundtrips_a_request() {
        let upstream = spawn_test_upstream(|_req| async move {
            let body = Full::new(Bytes::from_static(b"ok"))
                .map_err(|e: Infallible| match e {})
                .boxed_unsync();
            Ok(http::Response::builder().status(200).body(body).unwrap())
        });
        let (sender, conn) = handshake(upstream, Protocol::Http1)
            .await
            .expect("handshake");
        let req = http::Request::builder()
            .uri("/")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|e: Infallible| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = round_trip(sender, conn, req).await.expect("response");
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from_static(b"ok"));
    }

    #[tokio::test]
    async fn sender_is_clone() {
        let upstream = spawn_test_upstream(|_req| async move {
            let body = Full::new(Bytes::from_static(b"ok"))
                .map_err(|e: Infallible| match e {})
                .boxed_unsync();
            Ok(http::Response::builder().status(200).body(body).unwrap())
        });
        let (sender, _conn) = handshake(upstream, Protocol::Http1)
            .await
            .expect("handshake");
        // Clone is the load-bearing capability we rely on in `service_fn` —
        // verify the compile + runtime shape here so later refactors catch
        // a regression.
        // Reason: this clone is the entire point of the test (it verifies
        // `UpstreamSender: Clone`); clippy's "redundant" hint misses that.
        #[allow(clippy::redundant_clone)]
        let _clone = sender.clone();
    }
}
