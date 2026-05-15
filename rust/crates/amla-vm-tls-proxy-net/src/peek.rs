// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Pre-handshake SNI / ALPN peek over an async stream.
//!
//! `tokio_rustls::TlsAcceptor` consumes the `ClientHello` internally and only
//! exposes SNI after the handshake finishes. We need SNI *before* the
//! handshake — to decide whether to MITM at all, which leaf cert to mint,
//! and which ALPN protocols to offer back. So we read the `ClientHello`
//! bytes into a buffer, parse SNI + ALPN ourselves, then hand the
//! `TlsAcceptor` a [`ReplayStream`] that serves the buffered bytes first
//! and falls through to the underlying stream afterwards.
//!
//! Fail-closed: ECH, malformed records, non-TLS payloads, and oversized
//! `ClientHello`s (>32 KiB) all produce [`PeekError`] — never a silent
//! pass-through. Missing SNI is distinct so callers can require an explicit
//! destination-IP policy before proceeding.

use amla_tls_parse::{ParseOutcome, SniField, parse as parse_client_hello};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::{Instant, timeout};

/// Hard cap on buffered `ClientHello` bytes. A cooperating client fits
/// easily in 32 KiB even with post-quantum key shares (ML-KEM / Kyber).
const MAX_CLIENT_HELLO: usize = 32 * 1024;

/// Stream wrapper that serves `replay` bytes first, then falls through to
/// `inner`. Lets the caller un-consume a peeked `ClientHello` so a
/// downstream `TlsAcceptor` can read the same bytes again.
pub struct ReplayStream<S> {
    inner: S,
    replay: Vec<u8>,
    replay_pos: usize,
}

impl<S> ReplayStream<S> {
    const fn new(inner: S, replay: Vec<u8>) -> Self {
        Self {
            inner,
            replay,
            replay_pos: 0,
        }
    }

    #[cfg(test)]
    fn into_replay_and_inner(self) -> (Vec<u8>, S) {
        let unread = if self.replay_pos == 0 {
            self.replay
        } else {
            self.replay[self.replay_pos..].to_vec()
        };
        (unread, self.inner)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.replay_pos < self.replay.len() {
            let remaining = &self.replay[self.replay_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.replay_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Successful SNI peek result.
///
/// Only `hostname` is surfaced — it's the sole input MITM routing needs from
/// the `ClientHello`. ALPN selection for the guest-facing handshake is driven
/// by the MITM stack's own offer list, not by what the guest advertised.
#[derive(Debug)]
pub struct PeekInfo {
    pub hostname: String,
}

/// Reason a peek could not produce an SNI hostname.
///
/// The `ClientHello` is either corrupt, truncated, unsupported (ECH), not
/// actually TLS, or lacks SNI. Callers must surface a TLS alert and abort
/// unless they have an explicit policy for the particular error case.
///
/// `MissingSni` is structurally different: the `ClientHello` parsed cleanly
/// but omitted the SNI extension, which RFC 6066 explicitly permits for
/// clients connecting to IP-literal URLs (e.g. `https://10.0.0.1/`).
/// That is not enough to prove the client intended an IP-literal URL, so
/// callers that mint IP SAN certificates must still require an explicit
/// destination IP/subnet rule before substituting the TCP destination IP.
///
/// `NotClientHello` and `Malformed` cover adjacent-but-distinct cases:
/// `NotClientHello` means the record-layer framing is intact but the handshake
/// type byte isn't 0x01 (`ClientHello`) — e.g., a guest speaking a different
/// TLS sub-protocol or a misrouted non-TLS stream. `Malformed` means the bytes
/// looked like a TLS `ClientHello` but the internal structure is broken (bad
/// lengths, truncated extensions, etc.). Both map to the same TLS alert
/// response in practice; the distinction is for logging / metrics.
#[derive(Debug, thiserror::Error)]
pub enum PeekError {
    #[error("EOF before ClientHello completed")]
    Eof,
    #[error("ClientHello exceeds {MAX_CLIENT_HELLO} bytes")]
    Oversized,
    #[error("not a TLS ClientHello")]
    NotClientHello,
    #[error("malformed ClientHello: {0}")]
    Malformed(String),
    #[error("Encrypted Client Hello (ECH) not supported")]
    Ech,
    #[error("missing SNI")]
    MissingSni,
    #[error("timed out reading ClientHello after {0:?}")]
    TimedOut(Duration),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Read the guest's `ClientHello`, parse SNI + ALPN, and wrap the stream
/// so the parsed bytes can be replayed into `TlsAcceptor`.
///
/// On error the buffered bytes and underlying stream are returned inside the
/// [`ReplayStream`] so the caller can send a TLS alert or close cleanly.
#[cfg(test)]
pub async fn peek_sni<S>(
    stream: S,
) -> Result<(PeekInfo, ReplayStream<S>), (PeekError, ReplayStream<S>)>
where
    S: AsyncRead + Unpin,
{
    peek_sni_inner(stream, None).await
}

/// Read the guest's `ClientHello` with a total deadline.
///
/// The timeout covers the full `ClientHello`, not each individual socket
/// read, so slow-drip clients cannot keep the connection alive indefinitely.
pub async fn peek_sni_with_timeout<S>(
    stream: S,
    read_timeout: Duration,
) -> Result<(PeekInfo, ReplayStream<S>), (PeekError, ReplayStream<S>)>
where
    S: AsyncRead + Unpin,
{
    peek_sni_inner(stream, Some((Instant::now() + read_timeout, read_timeout))).await
}

async fn peek_sni_inner<S>(
    stream: S,
    deadline: Option<(Instant, Duration)>,
) -> Result<(PeekInfo, ReplayStream<S>), (PeekError, ReplayStream<S>)>
where
    S: AsyncRead + Unpin,
{
    let mut replay: Vec<u8> = Vec::with_capacity(1024);
    let mut scratch = [0u8; 4096];
    let mut stream = stream;

    loop {
        let read = stream.read(&mut scratch);
        let read = match deadline {
            Some((deadline, configured_timeout)) => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err((
                        PeekError::TimedOut(configured_timeout),
                        ReplayStream::new(stream, replay),
                    ));
                };
                match timeout(remaining, read).await {
                    Ok(read) => read,
                    Err(_) => {
                        return Err((
                            PeekError::TimedOut(configured_timeout),
                            ReplayStream::new(stream, replay),
                        ));
                    }
                }
            }
            None => read.await,
        };

        match read {
            Ok(0) => {
                return Err((PeekError::Eof, ReplayStream::new(stream, replay)));
            }
            Ok(n) => replay.extend_from_slice(&scratch[..n]),
            Err(e) => {
                return Err((PeekError::Io(e), ReplayStream::new(stream, replay)));
            }
        }

        if replay.len() > MAX_CLIENT_HELLO {
            return Err((PeekError::Oversized, ReplayStream::new(stream, replay)));
        }

        match parse_client_hello(&replay) {
            ParseOutcome::Incomplete => {}
            ParseOutcome::NotClientHello => {
                return Err((PeekError::NotClientHello, ReplayStream::new(stream, replay)));
            }
            ParseOutcome::Malformed(e) => {
                return Err((
                    PeekError::Malformed(e.to_string()),
                    ReplayStream::new(stream, replay),
                ));
            }
            ParseOutcome::Parsed(ch) => {
                if ch.has_ech {
                    return Err((PeekError::Ech, ReplayStream::new(stream, replay)));
                }
                let hostname = match ch.sni {
                    SniField::HostName(s) => s,
                    SniField::Absent => {
                        return Err((PeekError::MissingSni, ReplayStream::new(stream, replay)));
                    }
                };
                // RFC 7301: if present, `protocol_name_list` MUST NOT be
                // empty. Validate here as a fail-closed integrity check on
                // the incoming `ClientHello` — downstream never reads the
                // offered list (the MITM stack picks its own ALPN), but an
                // empty list still signals a malformed peer.
                if let Some(v) = &ch.alpn_offers
                    && v.is_empty()
                {
                    return Err((
                        PeekError::Malformed(
                            "ALPN extension present with empty protocol_name_list".to_string(),
                        ),
                        ReplayStream::new(stream, replay),
                    ));
                }
                let stream = ReplayStream::new(stream, replay);
                return Ok((PeekInfo { hostname }, stream));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Fixture builder uses `as u16`/`as u8` truncation for hand-rolled TLS
    // length fields; inputs are bounded by the test itself, so try_from()
    // would just add unwrap-noise.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    // Minimal ClientHello builder that matches the format amla_tls_parse
    // understands. Copied deliberately from the TLS inspector tests so this
    // crate doesn't take a dev-dep on policy-net just for fixtures.
    const TLS_HANDSHAKE: u8 = 22;
    const TLS_CLIENT_HELLO: u8 = 1;

    fn make_client_hello(sni: &str, alpn: &[&[u8]]) -> Vec<u8> {
        let mut hello = Vec::new();

        hello.push(TLS_HANDSHAKE);
        hello.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0, 0]);

        hello.push(TLS_CLIENT_HELLO);
        let handshake_len_pos = hello.len();
        hello.extend_from_slice(&[0, 0, 0]);

        let ch_start = hello.len();
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id length
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        hello.push(0x01);
        hello.push(0x00); // compression

        let ext_len_pos = hello.len();
        hello.extend_from_slice(&[0, 0]);
        let ext_start = hello.len();

        // SNI ext
        hello.extend_from_slice(&[0x00, 0x00]);
        let sni_bytes = sni.as_bytes();
        let sni_inner_len: u16 = (2 + 1 + 2 + sni_bytes.len()) as u16;
        hello.extend_from_slice(&sni_inner_len.to_be_bytes());
        let sni_list_len: u16 = sni_inner_len - 2;
        hello.extend_from_slice(&sni_list_len.to_be_bytes());
        hello.push(0x00);
        hello.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(sni_bytes);

        // ALPN ext
        if !alpn.is_empty() {
            hello.extend_from_slice(&[0x00, 0x10]); // ALPN type
            let mut alpn_list = Vec::new();
            for p in alpn {
                alpn_list.push(p.len() as u8);
                alpn_list.extend_from_slice(p);
            }
            let alpn_inner_len: u16 = (2 + alpn_list.len()) as u16;
            hello.extend_from_slice(&alpn_inner_len.to_be_bytes());
            hello.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
            hello.extend_from_slice(&alpn_list);
        }

        // Fill length fields
        let ext_len = (hello.len() - ext_start) as u16;
        hello[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

        let ch_len = hello.len() - ch_start;
        hello[handshake_len_pos] = ((ch_len >> 16) & 0xff) as u8;
        hello[handshake_len_pos + 1] = ((ch_len >> 8) & 0xff) as u8;
        hello[handshake_len_pos + 2] = (ch_len & 0xff) as u8;

        let record_len = (hello.len() - record_len_pos - 2) as u16;
        hello[record_len_pos..record_len_pos + 2].copy_from_slice(&record_len.to_be_bytes());

        hello
    }

    /// Fixture: a `ClientHello` whose ALPN extension is present but contains an
    /// empty `protocol_name_list` (forbidden by RFC 7301).
    fn make_client_hello_with_empty_alpn(sni: &str) -> Vec<u8> {
        let mut hello = Vec::new();

        hello.push(TLS_HANDSHAKE);
        hello.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0, 0]);

        hello.push(TLS_CLIENT_HELLO);
        let handshake_len_pos = hello.len();
        hello.extend_from_slice(&[0, 0, 0]);

        let ch_start = hello.len();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hello.push(0x01);
        hello.push(0x00);

        let ext_len_pos = hello.len();
        hello.extend_from_slice(&[0, 0]);
        let ext_start = hello.len();

        // SNI extension
        hello.extend_from_slice(&[0x00, 0x00]);
        let sni_bytes = sni.as_bytes();
        let sni_inner_len: u16 = (2 + 1 + 2 + sni_bytes.len()) as u16;
        hello.extend_from_slice(&sni_inner_len.to_be_bytes());
        let sni_list_len: u16 = sni_inner_len - 2;
        hello.extend_from_slice(&sni_list_len.to_be_bytes());
        hello.push(0x00);
        hello.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(sni_bytes);

        // ALPN extension with an explicit empty protocol_name_list:
        // ext_type=0x0010, ext_len=0x0002, list_len=0x0000 — present but empty.
        hello.extend_from_slice(&[0x00, 0x10]);
        hello.extend_from_slice(&[0x00, 0x02]);
        hello.extend_from_slice(&[0x00, 0x00]);

        let ext_len = (hello.len() - ext_start) as u16;
        hello[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());
        let ch_len = hello.len() - ch_start;
        hello[handshake_len_pos] = ((ch_len >> 16) & 0xff) as u8;
        hello[handshake_len_pos + 1] = ((ch_len >> 8) & 0xff) as u8;
        hello[handshake_len_pos + 2] = (ch_len & 0xff) as u8;
        let record_len = (hello.len() - record_len_pos - 2) as u16;
        hello[record_len_pos..record_len_pos + 2].copy_from_slice(&record_len.to_be_bytes());

        hello
    }

    #[tokio::test]
    async fn peek_extracts_sni() {
        let (mut client, server) = duplex(8192);
        let hello = make_client_hello("api.example.com", &[b"h2", b"http/1.1"]);
        tokio::spawn(async move {
            client.write_all(&hello).await.unwrap();
        });

        let (info, _stream) = peek_sni(server).await.unwrap_or_else(|(e, _)| {
            panic!("peek failed: {e}");
        });
        assert_eq!(info.hostname, "api.example.com");
    }

    #[tokio::test]
    async fn peeked_bytes_replay_through_stream() {
        // After peeking, a downstream consumer must be able to read the
        // exact bytes the guest sent — that's how TlsAcceptor consumes
        // the same ClientHello we just parsed.
        let (mut client, server) = duplex(8192);
        let hello = make_client_hello("replay.example.com", &[b"http/1.1"]);
        let hello_len = hello.len();
        let hello_clone = hello.clone();
        tokio::spawn(async move {
            client.write_all(&hello_clone).await.unwrap();
            // Follow with a sentinel the guest would send next.
            client.write_all(b"SENTINEL").await.unwrap();
        });

        let (_info, mut stream) = peek_sni(server).await.unwrap_or_else(|(e, _)| {
            panic!("peek failed: {e}");
        });

        let mut replayed = vec![0u8; hello_len];
        stream.read_exact(&mut replayed).await.unwrap();
        assert_eq!(replayed, hello);

        let mut sentinel = [0u8; 8];
        stream.read_exact(&mut sentinel).await.unwrap();
        assert_eq!(&sentinel, b"SENTINEL");
    }

    #[tokio::test]
    async fn peek_rejects_invalid_sni_as_malformed() {
        let (mut client, server) = duplex(8192);
        let hello = make_client_hello("", &[]);
        tokio::spawn(async move {
            client.write_all(&hello).await.unwrap();
        });
        let (err, _stream) = peek_sni(server).await.err().expect("must fail");
        assert!(
            matches!(err, PeekError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn peek_rejects_oversized_record_as_malformed() {
        // Craft a record that declares an impossible plaintext record size.
        // The parser rejects that before the stream-level buffer cap needs to
        // fire.
        let (mut client, server) = duplex(MAX_CLIENT_HELLO + 16384);
        tokio::spawn(async move {
            // Outer TLS record: type=Handshake(0x16), version=TLS1.2, len=65535
            client
                .write_all(&[0x16, 0x03, 0x03, 0xff, 0xff])
                .await
                .unwrap();
            // Handshake header: type=ClientHello(0x01), length=16 MiB - 1
            // (24-bit big-endian). Parser needs this many body bytes → stays
            // Incomplete.
            client.write_all(&[0x01, 0xff, 0xff, 0xff]).await.unwrap();
            // Dribble body bytes until the server side caps out.
            let body = vec![0u8; 4096];
            for _ in 0..(MAX_CLIENT_HELLO / 4096 + 4) {
                if client.write_all(&body).await.is_err() {
                    break;
                }
            }
        });
        let (err, _stream) = peek_sni(server).await.err().expect("must fail");
        assert!(
            matches!(err, PeekError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn into_replay_and_inner_returns_buffered_bytes() {
        let (mut client, server) = duplex(8192);
        let hello = make_client_hello("bypass.example.com", &[b"http/1.1"]);
        let expected = hello.clone();
        tokio::spawn(async move {
            client.write_all(&hello).await.unwrap();
        });
        let (_info, stream) = peek_sni(server).await.unwrap_or_else(|(e, _)| {
            panic!("peek failed: {e}");
        });
        let (replay, _inner) = stream.into_replay_and_inner();
        assert_eq!(replay, expected, "bypass path must carry full ClientHello");
    }

    #[tokio::test]
    async fn into_replay_and_inner_excludes_consumed_bytes() {
        // If the caller read some bytes from the ReplayStream before calling
        // `into_replay_and_inner`, only the UNREAD remainder is returned —
        // otherwise we'd double-forward already-processed bytes.
        let (mut client, server) = duplex(8192);
        let hello = make_client_hello("replay.example.com", &[b"http/1.1"]);
        let hello_len = hello.len();
        tokio::spawn(async move {
            client.write_all(&hello).await.unwrap();
        });
        let (_info, mut stream) = peek_sni(server).await.unwrap_or_else(|(e, _)| {
            panic!("peek failed: {e}");
        });
        let mut consumed = vec![0u8; 10];
        stream.read_exact(&mut consumed).await.unwrap();
        let (replay, _inner) = stream.into_replay_and_inner();
        assert_eq!(
            replay.len(),
            hello_len - 10,
            "only unread bytes must be in the returned replay",
        );
    }

    #[tokio::test]
    async fn peek_rejects_empty_alpn_list() {
        // RFC 7301: ALPN `protocol_name_list` MUST NOT be empty. A peek must
        // surface this as Malformed, not silently treat it as "no ALPN".
        let (mut client, server) = duplex(8192);
        tokio::spawn(async move {
            let hello = make_client_hello_with_empty_alpn("empty-alpn.example.com");
            client.write_all(&hello).await.unwrap();
        });
        let (err, _stream) = peek_sni(server).await.err().expect("must fail");
        assert!(
            matches!(err, PeekError::Malformed(ref msg) if msg.contains("empty")),
            "expected Malformed(empty ALPN), got {err:?}"
        );
    }

    #[tokio::test]
    async fn peek_rejects_eof_mid_hello() {
        let (mut client, server) = duplex(8192);
        tokio::spawn(async move {
            // Send one byte, then close.
            client.write_all(&[TLS_HANDSHAKE]).await.unwrap();
            drop(client);
        });
        let (err, _stream) = peek_sni(server).await.err().expect("must fail");
        assert!(matches!(err, PeekError::Eof), "expected Eof, got {err:?}");
    }
}
