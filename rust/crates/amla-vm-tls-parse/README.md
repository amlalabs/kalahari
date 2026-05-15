# amla-vm-tls-parse

Single source of truth for TLS `ClientHello` byte parsing in the Amla VM stack.

## What It Does

Pure byte-level parser for TLS 1.2/1.3 `ClientHello` messages. Takes a slice of accumulated TLS record bytes and returns a structured view: SNI hostname (if any), ALPN offer list (if any), and a flag for Encrypted Client Hello (ECH, extension 0xFE0D).

Handles handshake-message reassembly across multiple TLS records (RFC 5246 §6.2) — a large `ClientHello` with post-quantum key shares can legitimately span multiple records, each of which can be split across TCP segments.

## Key Types

- `parse(bytes) -> ParseOutcome` — core entry point; stateless, caller owns any buffering.
- `ParseOutcome` — `{Incomplete, Parsed(ClientHello), NotClientHello, Malformed(&'static str)}`.
- `ClientHello` — `{sni: SniField, alpn_offers: Option<Vec<Vec<u8>>>, has_ech: bool}`.
- `SniField` — `{Absent, HostName(String)}`; `HostName` is validated as an ASCII DNS hostname and canonicalized to lowercase. Malformed SNI makes the whole parse return `ParseOutcome::Malformed`.

## Semantics

Strict/fail-closed by default. Unknown SNI `name_type`, zero-length HostName, invalid DNS syntax, IP literals, invalid UTF-8, duplicate extensions, malformed ALPN, and invalid core `ClientHello` vector lengths return `Malformed`. ClientHello extension lengths and SNI list lengths must consume their enclosing buffers exactly. ECH detection never short-circuits — the parse still completes so callers see SNI and `has_ech` together and make their own policy choice.

## Where It Fits

Leaf-level crate with no amla dependencies (only `std`). Consumed by `amla-vm-policy-net` (IDS SNI allowlist) and `amla-vm-tls-proxy-net` (MITM SNI routing + ALPN check). Keeping the parser in one place prevents the two callers from drifting apart on record reassembly, extension walking, or ECH handling.

## License

AGPL-3.0-or-later OR BUSL-1.1
