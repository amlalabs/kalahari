# amla-vm-usernet

User-mode TCP/IP networking stack (slirp-like).

Crate: `amla-vm-usernet` (lib name `amla_usernet`).

## What It Does

User-space network backend for virtio-net, built on `smoltcp`. Provides NAT for outbound TCP/UDP, a DHCP server for guest configuration, and a DNS forwarder to the host resolver — all without root or `CAP_NET_ADMIN`. TCP policies and DNS interceptors can be attached for inspection or MITM.

Inbound port forwarding is implemented: `accept_inbound` bridges any `AsyncRead + AsyncWrite` stream to a guest TCP port, and `accept_inbound_udp` does the same for UDP via tokio `mpsc` channels.

## Key Types

- `UserNetBackend` — implements `amla_core::backends::NetBackend`. Holds the smoltcp interface, NAT proxy, and policy hooks behind a `Mutex`.
- `SharedBackend(Arc<UserNetBackend>)` — a `NetBackend` impl over a shared handle for callers that need both VMM wiring and `accept_inbound*`.
- `UserNetConfig` — network configuration (IPs, MACs, prefix lengths, port forwards).
- `UserNetError` / `UserNetResult<T>` — fallible operations.
- `UserNetStats` — RX/TX queue lengths and socket count.
- `InboundStream` — marker trait for streams accepted by `accept_inbound`.
- `PortForward`, `Protocol` — re-exports from `config`.
- `interceptor` — re-export of `amla_interceptor` (trait crate).

## Constructors

- `UserNetBackend::try_new(config) -> Result<Self, UserNetError>` — fallible, returns error on invalid config.
- `UserNetBackend::try_new_with_tcp_policy(config, policy) -> Result<Self, UserNetError>` — fallible, stores the TCP policy at construction.
- `UserNetBackend::try_new_with_policies(config, tcp_policy, dns_interceptor) -> Result<Self, UserNetError>` — stores concrete TCP and DNS policies at construction.

## Default Network

- Gateway: `10.0.2.2`
- Guest IP: `10.0.2.15`
- DNS: `10.0.2.2` (forwarder runs on the gateway)

Constants are re-exported from `amla_core::net` (`DEFAULT_GATEWAY`, `DEFAULT_GUEST_IP`, etc.).

## Where It Fits

Implements `NetBackend` from `amla-vm-core::backends`. Depends on `smoltcp` for the TCP/IP stack and `amla-vm-interceptor` for the interception trait. Used by `amla-vm-vmm` as the default network backend.

## Usage

```rust,no_run
use amla_usernet::{UserNetBackend, UserNetConfig};

let backend = UserNetBackend::try_new(UserNetConfig::default())?;
// Hand `backend` to the virtio-net device in amla-vm-vmm.
# Ok::<(), amla_usernet::UserNetError>(())
```

## Limitations

- IPv6 NAT is functional but not fully exercised in integration tests.
- ICMP echo is not proxied — guest pings will time out.
- MTU is fixed at 1500; jumbo frames are not supported.
- IPv6 DNS forwarding is not yet implemented (the `dns_server_v6` config field is reserved).

## License

AGPL-3.0-or-later OR BUSL-1.1
