# amla-vm-tls-proxy-net

TLS MITM proxy for HTTP request/response inspection and modification.

Crate: `amla-vm-tls-proxy-net` (lib name `amla_tls_proxy_net`).

## What It Does

Implements selective HTTPS interception through the owned-stream API in `amla-vm-interceptor`. `TlsMitmInterceptor` implements both `TcpConnectionPolicy` and `TrustedTcpInterceptor`, so usernet hands it the guest stream plus a deferred `HostConnector`. SNI is parsed and authorized before the host socket is opened.

Connections that fail SNI policy, have malformed ClientHello bytes, omit SNI without an explicit no-SNI destination IP rule, or fail certificate setup are denied to the guest without host connect.

## Key Types

- `TlsMitmInterceptor` — TCP policy and trusted interceptor. Constructed with `new(Arc<CertificateAuthority>, MitmPolicy, Arc<H>)`, `with_timeouts(..)`, or `with_host_tls_config(..)` for tests/custom trust.
- `CertificateAuthority` — on-the-fly leaf certificate generation with caching.
- `MitmPolicy` — selects ports/hosts/suffixes to MITM. Missing-SNI TLS is denied unless explicitly allowed with `intercept_no_sni_ip(...)` or `intercept_no_sni_subnet(...)`.
- `MitmTimeouts` — typed per-stage deadlines for ClientHello peeking, TLS handshakes, upstream initialization, response headers, and explicit bypass copying.
- `HttpMitmHandler` — user trait to inspect or rewrite parsed HTTP.

## Usage

```rust,no_run
use std::sync::Arc;
use amla_tls_proxy_net::{
    CertificateAuthority, MitmPolicy, TlsMitmInterceptor,
    handler::{HttpMitmHandler, HttpRequest, MitmAction},
};

struct MyHandler;
impl HttpMitmHandler for MyHandler {
    fn on_request(&self, req: &mut HttpRequest) -> MitmAction {
        req.headers.push(("X-Injected".into(), "1".into()));
        MitmAction::Forward
    }
}

let ca = Arc::new(CertificateAuthority::new()?);
let policy = MitmPolicy::builder().intercept_all_https().build();
let handler = Arc::new(MyHandler);
let interceptor = Arc::new(TlsMitmInterceptor::new(ca, policy, handler));

// Then attach to usernet:
// let backend = usernet.with_tcp_policy(interceptor);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Before any rustls operation, call `amla_tls_proxy_net::install_crypto_provider()` to install the `ring` default provider.

## License

AGPL-3.0-or-later OR BUSL-1.1
