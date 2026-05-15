# amla-vm-interceptor

Owned-stream traits for TCP and DNS interception.

Crate: `amla-vm-interceptor` (lib name `amla_interceptor`).

## What It Does

Defines the trait interface for deciding and executing guest TCP stream handling outside `amla-vm-usernet`. Usernet asks a `TcpConnectionPolicy` at SYN time whether to deny, explicitly connect directly, serve locally, hand the owned guest stream to trusted code with a deferred `HostConnector`, or abstain with `NoOpinion`.

The important inversion is `HostConnector`: trusted interceptors receive a connector capability, but no host socket is opened until the interceptor explicitly calls `connect()`.

`NoOpinion` is for partial policies. It means "this policy does not handle the flow," not "allow direct." Usernet treats a final `NoOpinion` as fail-closed. Use `FirstMatchTcpPolicy` or `NetworkSecurityBuilder` to compose partial policies and choose an explicit fallback such as default deny or direct passthrough.

## Key Types

- `TcpConnectionPolicy` — per-flow policy returning `TcpOpenAction`.
- `TcpOpenAction` — `NoOpinion`, `Deny`, `Direct`, `LocalService`, or `Intercept`.
- `FirstMatchTcpPolicy` — generic two-policy composition, skipping `NoOpinion` until a concrete action is returned.
- `NetworkSecurityBuilder` — builds the canonical fail-closed policy wrapper, with explicit opt-in direct passthrough.
- `TrustedTcpInterceptor` — owns a `LocalSocket`, `TcpFlow`, and `HostConnector`.
- `HostConnector` — one-shot deferred host connection.
- `LocalServiceHandler` — serves the guest directly with no host socket.
- `LocalSocket` — `AsyncRead + AsyncWrite` socket connected to the guest TCP stream.
- `DnsInterceptor` — UDP DNS hook returning `DnsAction::{Pass, Forward, Respond, Drop}`.
- `DnsResponseLimit` — backend-provided size token required to construct synthetic DNS responses.

## Usage

```rust,no_run
use amla_interceptor::{
    BoxFuture, LocalServiceHandler, LocalSocket, NetworkSecurityBuilder, TcpConnectionPolicy,
    TcpFlow, TcpOpenAction,
};

struct EchoPolicy;

impl TcpConnectionPolicy for EchoPolicy {
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        if flow.remote_addr.port() == 8080 {
            TcpOpenAction::LocalService(Box::new(EchoService))
        } else {
            TcpOpenAction::NoOpinion
        }
    }
}

fn tcp_policy() -> impl TcpConnectionPolicy {
    NetworkSecurityBuilder::new()
        .tcp_policy(EchoPolicy)
        .allow_direct_tcp()
        .build_tcp_policy()
}

struct EchoService;

impl LocalServiceHandler for EchoService {
    fn handle(self: Box<Self>, socket: LocalSocket) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut reader, mut writer) = socket.into_split();
            let mut buf = [0u8; 1024];
            let n = reader.read(&mut buf).await.unwrap_or(0);
            let _ = writer.write_all(&buf[..n]).await;
        })
    }
}
```

## License

AGPL-3.0-or-later OR BUSL-1.1
