// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
//! Owned-stream interceptor traits for TCP and DNS interception.
//!
//! TCP interception is decided at stream open time by [`TcpConnectionPolicy`].
//! The policy can deny the flow, connect it directly, serve it locally, or hand
//! an owned guest stream to trusted code with a deferred [`HostConnector`].
//!
//! - **Local service** ([`LocalServiceHandler`]) — receives a [`LocalSocket`]
//!   (`AsyncRead` + `AsyncWrite`) and serves the guest directly. No host connection
//!   is made. Implementers write the service the same way as a normal TCP server.
//!
//! - **Trusted interceptor** ([`TrustedTcpInterceptor`]) — owns the guest stream
//!   and may parse evidence before deciding whether to call [`HostConnector::connect`].
//!
//! A separate [`DnsInterceptor`] trait handles UDP DNS query interception.

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

pub use amla_policy_net::{DenyReason, TcpFlow};

/// A pinned, boxed, Send future. Used for async trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ── Owned stream policy API ─────────────────────────────────────────────

/// Host stream opened after stream policy has authorized upstream contact.
pub trait HostStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> HostStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Boxed host stream returned by [`HostConnector`].
pub type BoxHostStream = Box<dyn HostStream + 'static>;

/// Deferred connector for the real host socket.
///
/// Usernet creates this as an inert capability and passes it to a trusted
/// interceptor with the owned guest stream. The host socket is not opened until
/// trusted code explicitly awaits [`connect`](Self::connect), which is the
/// inversion needed for SNI/HTTP/body policy to run before upstream contact.
pub struct HostConnector {
    connect: Box<dyn FnOnce() -> BoxFuture<'static, io::Result<BoxHostStream>> + Send>,
}

impl HostConnector {
    /// Create a connector from a one-shot async function.
    pub fn new<F, Fut>(connect: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<BoxHostStream>> + Send + 'static,
    {
        Self {
            connect: Box::new(|| Box::pin(connect())),
        }
    }

    /// Open the host stream.
    pub async fn connect(self) -> io::Result<BoxHostStream> {
        (self.connect)().await
    }
}

/// TCP open action selected by stream policy.
pub enum TcpOpenAction {
    /// This policy has no opinion about the flow.
    ///
    /// Usernet treats this as fail-closed when it is the final decision. Policy
    /// composition layers use it to continue to the next policy without
    /// confusing "not mine" with an explicit direct-connection allow.
    NoOpinion,
    /// Deny and reset the guest flow.
    Deny(DenyReason),
    /// Explicitly allow a direct connection to the requested host address.
    Direct,
    /// Serve the guest from a local handler without opening a host socket.
    LocalService(Box<dyn LocalServiceHandler>),
    /// Hand the owned stream to trusted interception code.
    Intercept(Box<dyn TrustedTcpInterceptor>),
}

/// Policy consulted once for each outbound guest TCP flow.
pub trait TcpConnectionPolicy: Send + Sync {
    /// Select how usernet should handle this TCP flow.
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction;
}

/// Trusted owner of a guest TCP stream.
///
/// Implementations may parse guest bytes, consult policy, serve locally, mutate
/// data, or call [`HostConnector::connect`] after authorization permits host
/// contact.
pub trait TrustedTcpInterceptor: Send {
    /// Run the interceptor for one guest stream.
    fn run(
        self: Box<Self>,
        guest: LocalSocket,
        flow: TcpFlow,
        connector: HostConnector,
    ) -> BoxFuture<'static, ()>;
}

/// A policy that allows every TCP flow to connect directly.
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectTcpPolicy;

impl TcpConnectionPolicy for DirectTcpPolicy {
    fn open_tcp(&self, _flow: TcpFlow) -> TcpOpenAction {
        TcpOpenAction::Direct
    }
}

impl<P> TcpConnectionPolicy for Arc<P>
where
    P: TcpConnectionPolicy + ?Sized,
{
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        self.as_ref().open_tcp(flow)
    }
}

/// A policy that intentionally abstains for every TCP flow.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpinionTcpPolicy;

impl TcpConnectionPolicy for NoOpinionTcpPolicy {
    fn open_tcp(&self, _flow: TcpFlow) -> TcpOpenAction {
        TcpOpenAction::NoOpinion
    }
}

/// Fallback used by [`NetworkSecurityPolicy`] when its selector abstains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpPolicyFallback {
    /// Return [`TcpOpenAction::NoOpinion`].
    NoOpinion,
    /// Return [`TcpOpenAction::Deny`].
    Deny(DenyReason),
    /// Return [`TcpOpenAction::Direct`].
    Direct,
}

impl Default for TcpPolicyFallback {
    fn default() -> Self {
        Self::Deny(DenyReason::DefaultDeny)
    }
}

/// Generic two-policy composition. The first concrete action wins.
pub struct FirstMatchTcpPolicy<First, Second> {
    first: First,
    second: Second,
}

impl<First, Second> FirstMatchTcpPolicy<First, Second> {
    /// Create a first-match composition from two concrete policies.
    pub const fn new(first: First, second: Second) -> Self {
        Self { first, second }
    }
}

impl<First, Second> TcpConnectionPolicy for FirstMatchTcpPolicy<First, Second>
where
    First: TcpConnectionPolicy,
    Second: TcpConnectionPolicy,
{
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        match self.first.open_tcp(flow) {
            TcpOpenAction::NoOpinion => self.second.open_tcp(flow),
            action => action,
        }
    }
}

/// Final stream-security policy: one concrete selector plus a fallback.
///
/// The selector may return [`TcpOpenAction::NoOpinion`] for flows outside its
/// authority. The fallback then makes the security posture explicit.
pub struct NetworkSecurityPolicy<P> {
    tcp_policy: P,
    fallback: TcpPolicyFallback,
}

impl<P> NetworkSecurityPolicy<P> {
    /// Create a network security policy from a concrete TCP selector.
    pub const fn new(tcp_policy: P, fallback: TcpPolicyFallback) -> Self {
        Self {
            tcp_policy,
            fallback,
        }
    }

    fn fallback_action(&self) -> TcpOpenAction {
        match &self.fallback {
            TcpPolicyFallback::NoOpinion => TcpOpenAction::NoOpinion,
            TcpPolicyFallback::Deny(reason) => TcpOpenAction::Deny(reason.clone()),
            TcpPolicyFallback::Direct => TcpOpenAction::Direct,
        }
    }
}

impl<P> TcpConnectionPolicy for NetworkSecurityPolicy<P>
where
    P: TcpConnectionPolicy,
{
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        match self.tcp_policy.open_tcp(flow) {
            TcpOpenAction::NoOpinion => self.fallback_action(),
            action => action,
        }
    }
}

/// Builder for the canonical stream-security policy chain.
///
/// The builder starts fail-closed. Call [`allow_direct_tcp`](Self::allow_direct_tcp)
/// only when pass-through networking is intentionally part of the security
/// policy.
pub struct NetworkSecurityBuilder<P = NoOpinionTcpPolicy> {
    tcp_policy: P,
    fallback: TcpPolicyFallback,
}

impl Default for NetworkSecurityBuilder<NoOpinionTcpPolicy> {
    fn default() -> Self {
        Self {
            tcp_policy: NoOpinionTcpPolicy,
            fallback: TcpPolicyFallback::default(),
        }
    }
}

impl NetworkSecurityBuilder<NoOpinionTcpPolicy> {
    /// Start with no policies and a default-deny fallback.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<P> NetworkSecurityBuilder<P>
where
    P: TcpConnectionPolicy,
{
    /// Add a TCP stream policy to the chain.
    #[must_use]
    pub fn tcp_policy<Q>(self, policy: Q) -> NetworkSecurityBuilder<Q>
    where
        Q: TcpConnectionPolicy,
    {
        NetworkSecurityBuilder {
            tcp_policy: policy,
            fallback: self.fallback,
        }
    }

    /// Explicitly allow direct TCP for flows no policy handled.
    #[must_use]
    pub fn allow_direct_tcp(mut self) -> Self {
        self.fallback = TcpPolicyFallback::Direct;
        self
    }

    /// Explicitly deny TCP for flows no policy handled.
    #[must_use]
    pub fn deny_tcp(mut self, reason: DenyReason) -> Self {
        self.fallback = TcpPolicyFallback::Deny(reason);
        self
    }

    /// Build the composed TCP policy.
    pub fn build_tcp_policy(self) -> NetworkSecurityPolicy<P> {
        NetworkSecurityPolicy::new(self.tcp_policy, self.fallback)
    }
}

// ── Local service mode ──────────────────────────────────────────────────

/// Handler for a local service connection.
///
/// Receives a [`LocalSocket`] connected to the guest TCP stream and serves
/// it directly. The handler runs as a spawned async task — when it returns
/// (or the future is dropped), the TCP connection is closed.
pub trait LocalServiceHandler: Send {
    /// Handle a single connection. The socket is connected to the guest.
    fn handle(self: Box<Self>, socket: LocalSocket) -> BoxFuture<'static, ()>;
}

/// Bidirectional async socket connected to a guest TCP stream.
///
/// Implements [`AsyncRead`] and [`AsyncWrite`]. Use [`into_split()`](Self::into_split)
/// for concurrent read/write from separate tasks.
pub struct LocalSocket {
    read: LocalSocketRead,
    write: LocalSocketWrite,
}

impl LocalSocket {
    /// Create a new `LocalSocket` from channel endpoints.
    ///
    /// - `rx`: receives data from the guest (guest → service direction)
    /// - `tx`: sends data to the guest (service → guest direction).
    ///   Bounded so service writes apply async backpressure.
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            read: LocalSocketRead {
                rx,
                buf: Vec::new(),
                pos: 0,
            },
            write: LocalSocketWrite {
                tx: Some(PollSender::new(tx)),
            },
        }
    }

    /// Split into independent read and write halves for concurrent I/O.
    pub fn into_split(self) -> (LocalSocketRead, LocalSocketWrite) {
        (self.read, self.write)
    }
}

impl AsyncRead for LocalSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for LocalSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

/// Read half of a [`LocalSocket`].
///
/// Receives data from the guest TCP stream. Returns `Ok(())` with 0 bytes
/// read (EOF) when the guest closes its send direction (FIN).
pub struct LocalSocketRead {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl AsyncRead for LocalSocketRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain buffered data first.
        if self.pos < self.buf.len() {
            let remaining = &self.buf[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Poll for new data from the channel.
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    // Buffer the remainder.
                    self.buf = data;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Write half of a [`LocalSocket`].
///
/// Sends data to the guest TCP stream. Returns an error when the task loop
/// has shut down (the connection was closed).
pub struct LocalSocketWrite {
    tx: Option<PollSender<Vec<u8>>>,
}

const LOCAL_SOCKET_WRITE_CHUNK: usize = 16 * 1024;

impl AsyncWrite for LocalSocketWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let Some(tx) = self.get_mut().tx.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection shut down",
            )));
        };

        if ready!(tx.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            )));
        }

        let len = buf.len().min(LOCAL_SOCKET_WRITE_CHUNK);
        match tx.send_item(buf[..len].to_vec()) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().tx.take();
        Poll::Ready(Ok(()))
    }
}

/// Action for an intercepted DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum DnsAction<'a> {
    /// Forward to original destination unmodified.
    Pass,
    /// Forward to a different DNS server.
    Forward(std::net::SocketAddr),
    /// Reply with a synthetic DNS response payload (raw DNS wire format).
    Respond(DnsResponse<'a>),
    /// Drop the query silently.
    Drop,
}

impl<'a> DnsAction<'a> {
    /// Build a synthetic DNS response action after validating it fits.
    pub fn respond(
        limit: DnsResponseLimit,
        response: impl Into<Cow<'a, [u8]>>,
    ) -> Result<Self, DnsActionError> {
        Ok(Self::Respond(limit.validate(response)?))
    }
}

/// Maximum DNS response payload length the network backend can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsResponseLimit {
    max_len: usize,
}

impl DnsResponseLimit {
    /// Create a response limit in bytes.
    pub const fn new(max_len: usize) -> Self {
        Self { max_len }
    }

    /// Maximum response payload length in bytes.
    pub const fn max_len(self) -> usize {
        self.max_len
    }

    /// Validate a synthetic DNS response payload against this limit.
    pub fn validate<'a>(
        self,
        response: impl Into<Cow<'a, [u8]>>,
    ) -> Result<DnsResponse<'a>, DnsActionError> {
        let payload = response.into();
        let len = payload.len();
        if len > self.max_len {
            return Err(DnsActionError::ResponseTooLarge {
                len,
                max_len: self.max_len,
            });
        }
        Ok(DnsResponse { payload })
    }
}

/// Size-validated synthetic DNS response payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse<'a> {
    payload: Cow<'a, [u8]>,
}

impl DnsResponse<'_> {
    /// Raw DNS wire-format response bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// Response payload length in bytes.
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether the response payload is empty.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Rejected DNS interceptor action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsActionError {
    /// Synthetic DNS response exceeds the backend response limit.
    ResponseTooLarge {
        /// Response payload length in bytes.
        len: usize,
        /// Maximum allowed payload length in bytes.
        max_len: usize,
    },
}

impl std::fmt::Display for DnsActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResponseTooLarge { len, max_len } => {
                write!(f, "DNS response is {len} bytes, max {max_len}")
            }
        }
    }
}

impl std::error::Error for DnsActionError {}

/// Intercepts DNS queries (UDP port 53).
///
/// Orthogonal to [`TcpConnectionPolicy`] (TCP). When set on the network backend,
/// this is checked for ALL UDP packets to port 53 regardless of destination IP.
///
/// # Examples
///
/// ```
/// use amla_interceptor::{DnsInterceptor, DnsAction};
///
/// struct BlockAllDns;
///
/// impl DnsInterceptor for BlockAllDns {
///     fn intercept(
///         &self,
///         _query_payload: &[u8],
///         _original_dest: std::net::SocketAddr,
///         _guest_addr: std::net::SocketAddr,
///         _response_limit: amla_interceptor::DnsResponseLimit,
///     ) -> Result<DnsAction<'_>, amla_interceptor::DnsActionError> {
///         Ok(DnsAction::Drop)
///     }
/// }
/// ```
pub trait DnsInterceptor: Send + Sync {
    /// Called for each DNS query. `original_dest` is where the guest intended
    /// to send the query. `guest_addr` is the guest's source address.
    ///
    /// Synthetic responses must be built through [`DnsAction::respond`] with
    /// `response_limit`; oversized responses are rejected instead of being
    /// truncated or otherwise rewritten by the backend.
    fn intercept<'a>(
        &'a self,
        query_payload: &'a [u8],
        original_dest: SocketAddr,
        guest_addr: SocketAddr,
        response_limit: DnsResponseLimit,
    ) -> Result<DnsAction<'a>, DnsActionError>;
}

/// DNS policy that leaves queries unmodified.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDnsInterceptor;

impl DnsInterceptor for NoDnsInterceptor {
    fn intercept<'a>(
        &'a self,
        _query_payload: &'a [u8],
        _original_dest: SocketAddr,
        _guest_addr: SocketAddr,
        _response_limit: DnsResponseLimit,
    ) -> Result<DnsAction<'a>, DnsActionError> {
        Ok(DnsAction::Pass)
    }
}

impl<D> DnsInterceptor for Arc<D>
where
    D: DnsInterceptor + ?Sized,
{
    fn intercept<'a>(
        &'a self,
        query_payload: &'a [u8],
        original_dest: SocketAddr,
        guest_addr: SocketAddr,
        response_limit: DnsResponseLimit,
    ) -> Result<DnsAction<'a>, DnsActionError> {
        self.as_ref()
            .intercept(query_payload, original_dest, guest_addr, response_limit)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn traits_are_object_safe() {
        fn _takes_policy(_p: &dyn TcpConnectionPolicy) {}
        fn _takes_trusted(_i: Box<dyn TrustedTcpInterceptor>) {}
        fn _takes_handler(_h: Box<dyn LocalServiceHandler>) {}
    }

    #[tokio::test]
    async fn host_connector_is_lazy_until_connect() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_connector = Arc::clone(&calls);
        let connector = HostConnector::new(move || async move {
            calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let (stream, _peer) = tokio::io::duplex(64);
            Ok(Box::new(stream) as BoxHostStream)
        });

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let _stream = connector.connect().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dns_action_clone_eq() {
        let pass = DnsAction::Pass;
        assert_eq!(pass.clone(), DnsAction::Pass);

        let fwd = DnsAction::Forward("8.8.8.8:53".parse().unwrap());
        assert_eq!(fwd.clone(), fwd);

        let resp = DnsAction::respond(DnsResponseLimit::new(3), vec![1, 2, 3]).unwrap();
        assert_eq!(resp.clone(), resp);

        assert_eq!(DnsAction::Drop, DnsAction::Drop);
        assert_ne!(DnsAction::Pass, DnsAction::Drop);
    }

    #[test]
    fn dns_action_is_debug() {
        // Smoke-test: Debug doesn't panic on any variant.
        let _a = format!("{:?}", DnsAction::Pass);
        let _b = format!("{:?}", DnsAction::Forward("8.8.8.8:53".parse().unwrap()));
        let _c = format!(
            "{:?}",
            DnsAction::respond(DnsResponseLimit::new(3), vec![1, 2, 3])
        );
        let _d = format!("{:?}", DnsAction::Drop);
    }

    #[test]
    fn dns_interceptor_is_object_safe() {
        fn _takes_interceptor(_i: &dyn DnsInterceptor) {}
    }

    struct AbstainPolicy;

    impl TcpConnectionPolicy for AbstainPolicy {
        fn open_tcp(&self, _flow: TcpFlow) -> TcpOpenAction {
            TcpOpenAction::NoOpinion
        }
    }

    struct DirectPortPolicy(u16);

    impl TcpConnectionPolicy for DirectPortPolicy {
        fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
            if flow.remote_addr.port() == self.0 {
                TcpOpenAction::Direct
            } else {
                TcpOpenAction::NoOpinion
            }
        }
    }

    fn test_flow(port: u16) -> TcpFlow {
        TcpFlow::new(
            "10.0.2.15:12345".parse().unwrap(),
            format!("93.184.216.34:{port}").parse().unwrap(),
        )
    }

    #[test]
    fn network_security_builder_denies_final_no_opinion() {
        let policy = NetworkSecurityBuilder::new()
            .tcp_policy(AbstainPolicy)
            .build_tcp_policy();

        assert!(matches!(
            policy.open_tcp(test_flow(443)),
            TcpOpenAction::Deny(DenyReason::DefaultDeny)
        ));
    }

    #[test]
    fn network_security_builder_allows_explicit_direct_fallback() {
        let policy = NetworkSecurityBuilder::new()
            .tcp_policy(AbstainPolicy)
            .allow_direct_tcp()
            .build_tcp_policy();

        assert!(matches!(
            policy.open_tcp(test_flow(443)),
            TcpOpenAction::Direct
        ));
    }

    #[test]
    fn first_match_policy_skips_no_opinion_until_concrete_action() {
        let selector = FirstMatchTcpPolicy::new(AbstainPolicy, DirectPortPolicy(443));
        let policy = NetworkSecurityPolicy::new(selector, TcpPolicyFallback::default());

        assert!(matches!(
            policy.open_tcp(test_flow(443)),
            TcpOpenAction::Direct
        ));
        assert!(matches!(
            policy.open_tcp(test_flow(80)),
            TcpOpenAction::Deny(DenyReason::DefaultDeny)
        ));
    }

    struct TestDnsInterceptor;

    impl DnsInterceptor for TestDnsInterceptor {
        fn intercept<'a>(
            &'a self,
            query_payload: &'a [u8],
            _original_dest: SocketAddr,
            _guest_addr: SocketAddr,
            response_limit: DnsResponseLimit,
        ) -> Result<DnsAction<'a>, DnsActionError> {
            Ok(match query_payload.first() {
                Some(0) => DnsAction::Pass,
                Some(1) => DnsAction::Forward("8.8.8.8:53".parse().unwrap()),
                Some(2) => DnsAction::respond(response_limit, vec![0xDE, 0xAD])?,
                _ => DnsAction::Drop,
            })
        }
    }

    #[test]
    fn dns_interceptor_all_actions() {
        let dns = TestDnsInterceptor;
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let guest: SocketAddr = "10.0.2.15:12345".parse().unwrap();

        let response_limit = DnsResponseLimit::new(2);
        assert_eq!(
            dns.intercept(&[0], dest, guest, response_limit).unwrap(),
            DnsAction::Pass
        );
        assert_eq!(
            dns.intercept(&[1], dest, guest, response_limit).unwrap(),
            DnsAction::Forward("8.8.8.8:53".parse().unwrap())
        );
        assert_eq!(
            dns.intercept(&[2], dest, guest, response_limit).unwrap(),
            DnsAction::respond(response_limit, vec![0xDE, 0xAD]).unwrap()
        );
        assert_eq!(
            dns.intercept(&[99], dest, guest, response_limit).unwrap(),
            DnsAction::Drop
        );
    }

    #[test]
    fn dns_response_limit_rejects_oversized_payload() {
        assert_eq!(
            DnsAction::respond(DnsResponseLimit::new(2), vec![0xDE, 0xAD, 0xBE]),
            Err(DnsActionError::ResponseTooLarge { len: 3, max_len: 2 })
        );
    }

    #[tokio::test]
    async fn local_socket_read_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (guest_tx, guest_rx) = mpsc::channel(16);
        let (service_tx, mut service_rx) = mpsc::channel(16);

        let socket = LocalSocket::new(guest_rx, service_tx);
        let (mut reader, mut writer) = socket.into_split();

        // Guest sends data → service reads it.
        guest_tx.send(b"hello".to_vec()).await.unwrap();
        let mut buf = vec![0u8; 32];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // EOF after guest sender dropped.
        drop(guest_tx);
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        // Service writes data → task loop receives it.
        writer.write_all(b"response").await.unwrap();
        let received = service_rx.recv().await.unwrap();
        assert_eq!(received, b"response");
    }

    #[tokio::test]
    async fn local_socket_write_reports_partial_large_write() {
        use tokio::io::AsyncWriteExt;

        let (_guest_tx, guest_rx) = mpsc::channel(16);
        let (service_tx, mut service_rx) = mpsc::channel(16);

        let socket = LocalSocket::new(guest_rx, service_tx);
        let (_reader, mut writer) = socket.into_split();

        let payload = vec![0xA5; LOCAL_SOCKET_WRITE_CHUNK + 7];
        let n = writer.write(&payload).await.unwrap();
        assert_eq!(n, LOCAL_SOCKET_WRITE_CHUNK);

        let received = service_rx.recv().await.unwrap();
        assert_eq!(received.len(), LOCAL_SOCKET_WRITE_CHUNK);
        assert_eq!(received.as_slice(), &payload[..LOCAL_SOCKET_WRITE_CHUNK]);
    }

    #[tokio::test]
    async fn local_service_handler_trait() {
        struct EchoService;
        impl LocalServiceHandler for EchoService {
            fn handle(self: Box<Self>, socket: LocalSocket) -> BoxFuture<'static, ()> {
                Box::pin(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let (mut reader, mut writer) = socket.into_split();
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if writer.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                })
            }
        }

        let (guest_tx, guest_rx) = mpsc::channel(16);
        let (service_tx, mut service_rx) = mpsc::channel(16);
        let socket = LocalSocket::new(guest_rx, service_tx);

        let handler = Box::new(EchoService);
        let handle = tokio::spawn(handler.handle(socket));

        // Send data from guest → service → back.
        guest_tx.send(b"ping".to_vec()).await.unwrap();
        let echoed = service_rx.recv().await.unwrap();
        assert_eq!(echoed, b"ping");

        // Close guest side → handler exits.
        drop(guest_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn local_socket_shutdown_signals_eof() {
        use tokio::io::AsyncWriteExt;

        let (_guest_tx, guest_rx) = mpsc::channel(16);
        let (service_tx, mut service_rx) = mpsc::channel(16);

        let socket = LocalSocket::new(guest_rx, service_tx);
        let (_reader, mut writer) = socket.into_split();

        // Write some data, then shutdown.
        writer.write_all(b"data").await.unwrap();
        let received = service_rx.recv().await.unwrap();
        assert_eq!(received, b"data");

        writer.shutdown().await.unwrap();

        // After shutdown, the channel is closed — recv returns None.
        assert!(service_rx.recv().await.is_none());

        // Further writes should fail with BrokenPipe.
        let err = writer.write_all(b"more").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
