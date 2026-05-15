// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Per-connection async proxy orchestration.
//!
//! [`run_proxy_owned`] owns the full MITM lifecycle for one guest TCP
//! connection: `ClientHello` peek, policy check, guest TLS handshake, lazy host
//! connect/handshake, hyper server + upstream actor wiring, and teardown.

use std::io;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use amla_interceptor::{HostConnector, LocalSocket, TcpFlow};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

use crate::MitmTimeouts;
use crate::ca::CertificateAuthority;
use crate::handler::HttpMitmHandler;
use crate::mitm::{alert, service, upstream, xlate};
use crate::peek::{PeekError, peek_sni_with_timeout};
use crate::policy::MitmPolicy;

/// Orchestrates a single MITM connection using the owned-stream interceptor
/// API. Unlike [`run_proxy`], this runner owns the guest TCP stream and can
/// either MITM it or, when policy explicitly allows, pass it through to a
/// direct host stream.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_proxy_owned<H: HttpMitmHandler>(
    guest: LocalSocket,
    flow: TcpFlow,
    connector: HostConnector,
    ca: Arc<CertificateAuthority>,
    policy: MitmPolicy,
    handler: Arc<H>,
    host_tls_config: Arc<rustls::ClientConfig>,
    timeouts: MitmTimeouts,
) {
    // 1. Peek SNI before any host connect.
    let (hostname, mut guest_stream, no_sni_ip_identity) = match peek_sni_with_timeout(
        guest,
        timeouts.client_hello(),
    )
    .await
    {
        Ok((peek, stream)) => (peek.hostname, stream, false),
        Err((PeekError::MissingSni, mut stream)) => {
            if !policy.should_intercept_no_sni_ip(flow.remote_addr) {
                log::debug!(
                    "MITM owned-stream denying missing-SNI flow {flow:?}; no explicit no-SNI IP rule"
                );
                if let Err(write_err) = stream.write_all(&alert::FATAL_UNRECOGNIZED_NAME).await {
                    log::debug!(
                        "tls-proxy owned alert write (missing SNI for {flow:?}) failed: {write_err}"
                    );
                }
                if let Err(shutdown_err) = stream.shutdown().await {
                    log::debug!(
                        "tls-proxy owned shutdown (missing SNI for {flow:?}) failed: {shutdown_err}"
                    );
                }
                return;
            }

            let ip_host = flow.remote_addr.ip().to_string();
            log::debug!(
                "MITM owned-stream ClientHello has no SNI; using explicit no-SNI IP rule for {ip_host}"
            );
            (ip_host, stream, true)
        }
        Err((e, mut stream)) => {
            log::debug!("MITM owned-stream peek failed: {e}");
            if let Err(write_err) = stream.write_all(alert::for_peek_error(&e)).await {
                log::debug!("tls-proxy owned alert write (peek failure) failed: {write_err}");
            }
            if let Err(shutdown_err) = stream.shutdown().await {
                log::debug!("tls-proxy owned shutdown (peek failure) failed: {shutdown_err}");
            }
            return;
        }
    };
    log::trace!(
        "MITM owned-stream peek success: hostname={hostname:?}, no_sni_ip_identity={no_sni_ip_identity}"
    );

    // 2. Policy: host mismatch fails closed. The TCP layer selected this
    // trusted interceptor based on destination address; SNI is additional
    // evidence, not a passthrough authorization.
    if !no_sni_ip_identity && !policy.should_intercept_host(&hostname) {
        log::debug!("MITM owned-stream denying host {hostname:?} for flow {flow:?}");
        if let Err(write_err) = guest_stream
            .write_all(&alert::FATAL_UNRECOGNIZED_NAME)
            .await
        {
            log::debug!(
                "tls-proxy owned alert write (SNI policy mismatch {hostname:?}) failed: {write_err}"
            );
        }
        if let Err(shutdown_err) = guest_stream.shutdown().await {
            log::debug!(
                "tls-proxy owned shutdown (SNI policy mismatch {hostname:?}) failed: {shutdown_err}"
            );
        }
        return;
    }

    // 3. Validate the upstream server name before host connect.
    let server_name = match ServerName::try_from(hostname.clone()) {
        Ok(sn) => sn,
        Err(e) => {
            log::debug!("invalid server name {hostname:?}: {e}");
            if let Err(write_err) = guest_stream
                .write_all(&alert::FATAL_UNRECOGNIZED_NAME)
                .await
            {
                log::debug!(
                    "tls-proxy owned alert write (invalid server name {hostname:?}) failed: {write_err}"
                );
            }
            if let Err(shutdown_err) = guest_stream.shutdown().await {
                log::debug!(
                    "tls-proxy owned shutdown (invalid server name {hostname:?}) failed: {shutdown_err}"
                );
            }
            return;
        }
    };

    // 4. Mint the guest-facing cert before host connect. If CA work fails,
    // fail closed to the guest without touching the host.
    let leaf = match ca.get_leaf_cert(&hostname) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("MITM owned leaf cert mint for {hostname:?} failed: {e}");
            if let Err(write_err) = guest_stream
                .write_all(&alert::FATAL_HANDSHAKE_FAILURE)
                .await
            {
                log::debug!(
                    "tls-proxy owned alert write (leaf cert mint for {hostname:?}) failed: {write_err}"
                );
            }
            if let Err(shutdown_err) = guest_stream.shutdown().await {
                log::debug!(
                    "tls-proxy owned shutdown (leaf cert mint for {hostname:?}) failed: {shutdown_err}"
                );
            }
            return;
        }
    };
    let alpn_offers = [b"h2".to_vec(), b"http/1.1".to_vec()];
    let guest_config = match crate::ca::build_guest_tls_config(&leaf, &ca, &alpn_offers) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("MITM owned guest TLS config failed: {e}");
            if let Err(write_err) = guest_stream
                .write_all(&alert::FATAL_HANDSHAKE_FAILURE)
                .await
            {
                log::debug!("tls-proxy owned alert write (guest TLS config) failed: {write_err}");
            }
            if let Err(shutdown_err) = guest_stream.shutdown().await {
                log::debug!("tls-proxy owned shutdown (guest TLS config) failed: {shutdown_err}");
            }
            return;
        }
    };

    // 5. Accept guest TLS now. The host leg remains lazy until an HTTP
    // request actually needs forwarding, so request-header blocks never
    // contact the origin.
    let guest_acceptor = TlsAcceptor::from(Arc::new(guest_config));
    let guest_tls = match timeout(
        timeouts.guest_tls_handshake(),
        guest_acceptor.accept(guest_stream),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            log::debug!("owned guest TLS handshake failed for {hostname:?}: {e}");
            return;
        }
        Err(_) => {
            log::warn!(
                "owned guest TLS handshake timed out for {hostname:?} after {:?}",
                timeouts.guest_tls_handshake(),
            );
            return;
        }
    };

    let guest_proto = match upstream::negotiated_protocol(guest_tls.get_ref().1.alpn_protocol()) {
        Ok(p) => p,
        Err(bytes) => {
            log::warn!(
                "MITM owned: unexpected guest ALPN for {hostname:?}: {:?}",
                String::from_utf8_lossy(&bytes)
            );
            return;
        }
    };

    let hostname = Arc::new(hostname);
    let hostname_for_log = Arc::clone(&hostname);
    let origin = Arc::new(xlate::OriginAuthority::new(
        (*hostname).clone(),
        flow.remote_addr.port(),
    ));
    let upstream = upstream::UpstreamEndpoint::lazy(upstream::LazyUpstream::new(
        connector,
        server_name,
        (*hostname).clone(),
        host_tls_config,
        timeouts,
    ));
    let svc = service_fn(move |req| {
        let handler = Arc::clone(&handler);
        let upstream = upstream.clone();
        let origin = Arc::clone(&origin);
        service::proxy_request(req, handler, upstream, origin, guest_proto, timeouts)
    });

    #[allow(clippy::items_after_statements)]
    type ServeError = Box<dyn std::error::Error + Send + Sync>;
    let guest_io = TokioIo::new(guest_tls);
    let serve_fut = async move {
        let r: Result<(), ServeError> = match guest_proto {
            upstream::Protocol::Http1 => hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(guest_io, svc)
                .await
                .map_err(Into::into),
            upstream::Protocol::Http2 => {
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(guest_io, svc)
                    .await
                    .map_err(Into::into)
            }
        };
        r
    };

    if let Err(e) = serve_fut.await {
        let src = std::error::Error::source(&*e);
        let is_client_hangup = src
            .and_then(|s| s.downcast_ref::<io::Error>())
            .is_some_and(|ioe| {
                matches!(
                    ioe.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                )
            });
        if is_client_hangup {
            log::trace!(
                "MITM owned guest {guest_proto:?} serve_connection for {hostname_for_log:?} \
                 ended from client hangup: {e}"
            );
        } else {
            log::warn!(
                "MITM owned guest {guest_proto:?} serve_connection for {hostname_for_log:?} \
                 ended with error: {e:#} (source: {src:?})"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::MitmAction;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[test]
    fn negotiated_protocol_maps_alpn_bytes() {
        assert_eq!(
            upstream::negotiated_protocol(Some(b"h2")),
            Ok(upstream::Protocol::Http2)
        );
        assert_eq!(
            upstream::negotiated_protocol(Some(b"http/1.1")),
            Ok(upstream::Protocol::Http1)
        );
        // Absent ALPN is legitimate (RFC 2818): treat as h1.
        assert_eq!(
            upstream::negotiated_protocol(None),
            Ok(upstream::Protocol::Http1)
        );
        // Peer picked an ALPN we never offered: contract violation; bytes
        // echoed back so the caller can log them.
        assert_eq!(
            upstream::negotiated_protocol(Some(b"spdy/3.1")),
            Err(b"spdy/3.1".to_vec())
        );
    }

    struct NoopHandler;

    impl HttpMitmHandler for NoopHandler {}

    fn client_hello(hostname: &str) -> Vec<u8> {
        crate::install_crypto_provider();
        let config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(hostname.to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(config, server_name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[tokio::test]
    async fn owned_proxy_client_hello_timeout_fails_closed_without_connecting() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let policy = MitmPolicy::builder()
            .intercept_host("allowed.example.com")
            .build()
            .unwrap();
        let handler = Arc::new(NoopHandler);
        let host_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let (_guest_tx, guest_rx) = mpsc::channel(16);
        let (to_guest_tx, mut to_guest_rx) = mpsc::channel(16);
        let guest = LocalSocket::new(guest_rx, to_guest_tx);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_for_connector = Arc::clone(&connect_calls);
        let connector = HostConnector::new(move || async move {
            connect_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(4096);
            Ok(Box::new(stream) as amla_interceptor::BoxHostStream)
        });
        let flow = TcpFlow::new(
            "10.0.2.15:49152".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );
        let timeouts = MitmTimeouts::default()
            .with_client_hello(Duration::from_millis(20))
            .unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            run_proxy_owned(
                guest,
                flow,
                connector,
                ca,
                policy,
                handler,
                host_tls_config,
                timeouts,
            ),
        )
        .await
        .unwrap();

        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);
        let guest_bytes = to_guest_rx.try_recv().unwrap();
        assert_eq!(guest_bytes, alert::FATAL_HANDSHAKE_FAILURE);
    }

    #[tokio::test]
    async fn owned_proxy_denies_host_mismatch_without_connecting() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let policy = MitmPolicy::builder()
            .intercept_host("allowed.example.com")
            .build()
            .unwrap();
        let handler = Arc::new(NoopHandler);
        let host_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let (guest_tx, guest_rx) = mpsc::channel(16);
        let (to_guest_tx, mut to_guest_rx) = mpsc::channel(16);
        let guest = LocalSocket::new(guest_rx, to_guest_tx);

        guest_tx
            .send(client_hello("blocked.example.com"))
            .await
            .unwrap();
        drop(guest_tx);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_for_connector = Arc::clone(&connect_calls);
        let connector = HostConnector::new(move || async move {
            connect_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(4096);
            Ok(Box::new(stream) as amla_interceptor::BoxHostStream)
        });
        let flow = TcpFlow::new(
            "10.0.2.15:49152".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            run_proxy_owned(
                guest,
                flow,
                connector,
                ca,
                policy,
                handler,
                host_tls_config,
                MitmTimeouts::default(),
            ),
        )
        .await
        .unwrap();

        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);
        let guest_bytes = to_guest_rx.try_recv().unwrap();
        assert_eq!(guest_bytes, alert::FATAL_UNRECOGNIZED_NAME);
    }

    struct BlockAllHandler;

    impl HttpMitmHandler for BlockAllHandler {
        async fn on_request_headers(
            &self,
            _req: &mut crate::handler::HttpRequestHeaders,
        ) -> MitmAction {
            MitmAction::block_status(http::StatusCode::FORBIDDEN)
        }
    }

    #[tokio::test]
    async fn owned_proxy_request_header_block_does_not_connect_upstream() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let policy = MitmPolicy::builder()
            .intercept_host("allowed.example.com")
            .build()
            .unwrap();
        let handler = Arc::new(BlockAllHandler);
        let host_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let (guest_to_proxy_tx, guest_to_proxy_rx) = mpsc::channel(16);
        let (proxy_to_guest_tx, proxy_to_guest_rx) = mpsc::channel(16);
        let guest = LocalSocket::new(guest_to_proxy_rx, proxy_to_guest_tx);
        let client_io = LocalSocket::new(proxy_to_guest_rx, guest_to_proxy_tx);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_for_connector = Arc::clone(&connect_calls);
        let connector = HostConnector::new(move || async move {
            connect_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(1024);
            Ok(Box::new(stream) as amla_interceptor::BoxHostStream)
        });
        let flow = TcpFlow::new(
            "10.0.2.15:49152".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );

        let proxy_task = tokio::spawn(run_proxy_owned(
            guest,
            flow,
            connector,
            ca.clone(),
            policy,
            handler,
            host_tls_config,
            MitmTimeouts::default(),
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_cert_der().clone()).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(client_config)
            .connect(server_name, client_io)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(async move {
            drop(conn.await);
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);

        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn owned_proxy_missing_sni_denies_without_explicit_ip_policy() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let policy = MitmPolicy::builder().intercept_all_https().build().unwrap();
        let handler = Arc::new(NoopHandler);
        let host_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let (guest_tx, guest_rx) = mpsc::channel(16);
        let (to_guest_tx, mut to_guest_rx) = mpsc::channel(16);
        let guest = LocalSocket::new(guest_rx, to_guest_tx);

        guest_tx.send(client_hello("127.0.0.1")).await.unwrap();
        drop(guest_tx);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_for_connector = Arc::clone(&connect_calls);
        let connector = HostConnector::new(move || async move {
            connect_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(1024);
            Ok(Box::new(stream) as amla_interceptor::BoxHostStream)
        });
        let flow = TcpFlow::new(
            "10.0.2.15:49152".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            run_proxy_owned(
                guest,
                flow,
                connector,
                ca,
                policy,
                handler,
                host_tls_config,
                MitmTimeouts::default(),
            ),
        )
        .await
        .unwrap();

        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);
        let guest_bytes = to_guest_rx.try_recv().unwrap();
        assert_eq!(guest_bytes, alert::FATAL_UNRECOGNIZED_NAME);
    }

    #[tokio::test]
    async fn owned_proxy_ip_literal_sni_requires_matching_host_policy() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let policy = MitmPolicy::builder()
            .intercept_host("allowed.example.com")
            .build()
            .unwrap();
        let handler = Arc::new(NoopHandler);
        let host_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let (guest_tx, guest_rx) = mpsc::channel(16);
        let (to_guest_tx, mut to_guest_rx) = mpsc::channel(16);
        let guest = LocalSocket::new(guest_rx, to_guest_tx);

        guest_tx.send(client_hello("127.0.0.1")).await.unwrap();
        drop(guest_tx);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_for_connector = Arc::clone(&connect_calls);
        let connector = HostConnector::new(move || async move {
            connect_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(1024);
            Ok(Box::new(stream) as amla_interceptor::BoxHostStream)
        });
        let flow = TcpFlow::new(
            "10.0.2.15:49152".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            run_proxy_owned(
                guest,
                flow,
                connector,
                ca,
                policy,
                handler,
                host_tls_config,
                MitmTimeouts::default(),
            ),
        )
        .await
        .unwrap();

        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);
        let guest_bytes = to_guest_rx.try_recv().unwrap();
        assert_eq!(guest_bytes, alert::FATAL_UNRECOGNIZED_NAME);
    }

    #[tokio::test]
    async fn owned_proxy_missing_sni_ip_requires_explicit_policy() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let policy = MitmPolicy::builder()
            .intercept_no_sni_ip("127.0.0.1".parse().unwrap())
            .build()
            .unwrap();
        let handler = Arc::new(BlockAllHandler);
        let host_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let (guest_to_proxy_tx, guest_to_proxy_rx) = mpsc::channel(16);
        let (proxy_to_guest_tx, proxy_to_guest_rx) = mpsc::channel(16);
        let guest = LocalSocket::new(guest_to_proxy_rx, proxy_to_guest_tx);
        let client_io = LocalSocket::new(proxy_to_guest_rx, guest_to_proxy_tx);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_for_connector = Arc::clone(&connect_calls);
        let connector = HostConnector::new(move || async move {
            connect_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(1024);
            Ok(Box::new(stream) as amla_interceptor::BoxHostStream)
        });
        let flow = TcpFlow::new(
            "10.0.2.15:49152".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );

        let proxy_task = tokio::spawn(run_proxy_owned(
            guest,
            flow,
            connector,
            ca.clone(),
            policy,
            handler,
            host_tls_config,
            MitmTimeouts::default(),
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_cert_der().clone()).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(client_config)
            .connect(server_name, client_io)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(async move {
            drop(conn.await);
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);

        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .unwrap()
            .unwrap();
    }
}
