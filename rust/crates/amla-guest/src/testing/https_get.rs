//! Minimal HTTPS GET client for guest VM integration tests.
//!
//! Designed to run inside a guest VM as a lightweight HTTPS client.
//! Uses rustls for TLS.
//!
//! Usage: `amla_https_get <url> [--ca-cert <path>] [--method <method>]`
//!        `[--header <name:value>] [--body <body>]`
//!
//! Without `--ca-cert`, certificate verification is disabled (equivalent to
//! wget's `--no-check-certificate`).

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;

struct RequestOptions {
    url: String,
    ca_path: Option<String>,
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> i32 {
    let opts = parse_args(args);
    let (host, port, path) = parse_url(&opts.url);

    // Install default crypto provider. install_default() returns Err if the
    // provider was already installed — harmless in this one-shot binary but
    // worth surfacing so multiple concurrent callers would be visible.
    if let Err(_prev) = rustls::crypto::ring::default_provider().install_default() {
        eprintln!("https_get: default crypto provider already installed; continuing");
    }

    let config = build_tls_config(opts.ca_path.as_deref());

    // TCP connect — re-bracket IPv6 addresses for socket address format
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("TCP connect to {addr} failed: {e}");
        std::process::exit(1);
    });
    // Best-effort; not all platforms support socket timeouts
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    // TLS handshake
    // For IP addresses, use the IP directly as ServerName
    let server_name = host.parse::<std::net::IpAddr>().map_or_else(
        |_| {
            rustls::pki_types::ServerName::try_from(host.clone()).unwrap_or_else(|e| {
                eprintln!("Invalid server name '{host}': {e}");
                std::process::exit(1);
            })
        },
        rustls::pki_types::ServerName::from,
    );

    let conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap_or_else(|e| {
        eprintln!("TLS connection setup failed: {e}");
        std::process::exit(1);
    });
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let request = build_request(&opts, &host, port, &path);
    tls.write_all(request.as_bytes()).unwrap_or_else(|e| {
        eprintln!("HTTP write failed: {e}");
        std::process::exit(1);
    });
    if !opts.body.is_empty() {
        tls.write_all(&opts.body).unwrap_or_else(|e| {
            eprintln!("HTTP body write failed: {e}");
            std::process::exit(1);
        });
    }
    tls.flush().unwrap_or_else(|e| {
        eprintln!("HTTP flush failed: {e}");
        std::process::exit(1);
    });

    // Read response
    let mut response = Vec::new();
    let read_error = match tls.read_to_end(&mut response) {
        Ok(_) => false,
        Err(e) => {
            // TLS close_notify or connection reset — data read so far may be valid
            eprintln!(
                "read_to_end: {e} (got {} bytes before error)",
                response.len()
            );
            true
        }
    };
    let response_str = String::from_utf8_lossy(&response);

    // Print full response (headers + body) and flush
    print!("{response_str}");
    std::io::stdout().flush().unwrap_or_else(|e| {
        eprintln!("stdout flush: {e}");
    });

    // Exit nonzero if read failed with no data (real failure vs close_notify)
    if read_error && response.is_empty() {
        return 1;
    }
    0
}

#[allow(clippy::too_many_lines)]
fn parse_args(args: &[String]) -> RequestOptions {
    use lexopt::prelude::*;

    let mut url: Option<String> = None;
    let mut ca_path: Option<String> = None;
    let mut method = "GET".to_string();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut parser = lexopt::Parser::from_args(args.iter().map(String::as_str));

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("argument error: {e}");
        std::process::exit(1);
    }) {
        match arg {
            Long("ca-cert") => {
                ca_path = Some(
                    parser
                        .value()
                        .unwrap_or_else(|e| {
                            eprintln!("--ca-cert requires a value: {e}");
                            std::process::exit(1);
                        })
                        .into_string()
                        .unwrap_or_else(|_| {
                            eprintln!("--ca-cert value is not valid UTF-8");
                            std::process::exit(1);
                        }),
                );
            }
            Long("method") => {
                method = parser
                    .value()
                    .unwrap_or_else(|e| {
                        eprintln!("--method requires a value: {e}");
                        std::process::exit(1);
                    })
                    .into_string()
                    .unwrap_or_else(|_| {
                        eprintln!("--method value is not valid UTF-8");
                        std::process::exit(1);
                    });
            }
            Long("header") => {
                let raw = parser
                    .value()
                    .unwrap_or_else(|e| {
                        eprintln!("--header requires a value: {e}");
                        std::process::exit(1);
                    })
                    .into_string()
                    .unwrap_or_else(|_| {
                        eprintln!("--header value is not valid UTF-8");
                        std::process::exit(1);
                    });
                headers.push(parse_header_arg(&raw));
            }
            Long("body") => {
                body = parser
                    .value()
                    .unwrap_or_else(|e| {
                        eprintln!("--body requires a value: {e}");
                        std::process::exit(1);
                    })
                    .into_string()
                    .unwrap_or_else(|_| {
                        eprintln!("--body value is not valid UTF-8");
                        std::process::exit(1);
                    })
                    .into_bytes();
            }
            Short('h') | Long("help") => {
                eprintln!(
                    "Usage: amla_https_get <url> [--ca-cert <path>] \
                     [--method <method>] [--header <name:value>] [--body <body>]"
                );
                eprintln!();
                eprintln!("Minimal HTTPS GET client for guest VM integration tests.");
                eprintln!("Without --ca-cert, certificate verification is disabled.");
                std::process::exit(0);
            }
            Value(val) if url.is_none() => {
                url = Some(val.into_string().unwrap_or_else(|_| {
                    eprintln!("URL is not valid UTF-8");
                    std::process::exit(1);
                }));
            }
            _ => {
                eprintln!("unexpected argument: {}", arg.unexpected());
                std::process::exit(1);
            }
        }
    }

    let url = url.unwrap_or_else(|| {
        eprintln!(
            "Usage: amla_https_get <url> [--ca-cert <path>] \
             [--method <method>] [--header <name:value>] [--body <body>]"
        );
        std::process::exit(1);
    });

    validate_no_ctl("method", &method);
    if method.is_empty() || method.chars().any(char::is_whitespace) {
        eprintln!("Invalid HTTP method: {method:?}");
        std::process::exit(1);
    }

    RequestOptions {
        url,
        ca_path,
        method,
        headers,
        body,
    }
}

fn parse_header_arg(raw: &str) -> (String, String) {
    let Some((name, value)) = raw.split_once(':') else {
        eprintln!("--header must be in name:value form");
        std::process::exit(1);
    };
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    validate_no_ctl("header name", &name);
    validate_no_ctl("header value", &value);
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        eprintln!("Invalid header name: {name:?}");
        std::process::exit(1);
    }
    (name, value)
}

fn validate_no_ctl(field: &str, value: &str) {
    if value.chars().any(|c| matches!(c, '\r' | '\n')) {
        eprintln!("{field} must not contain CR/LF");
        std::process::exit(1);
    }
}

fn build_request(opts: &RequestOptions, host: &str, port: u16, path: &str) -> String {
    // Build Host header per RFC 7230 §5.4:
    // Include port when non-default; bracket IPv6 addresses
    let host_header = build_host_header(host, port);
    let mut request = format!("{} {path} HTTP/1.1\r\nHost: {host_header}\r\n", opts.method);
    let has_content_length = opts
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    for (name, value) in &opts.headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !opts.body.is_empty()
        && !has_content_length
        && write!(request, "Content-Length: {}\r\n", opts.body.len()).is_err()
    {
        eprintln!("failed to build HTTP request");
        std::process::exit(1);
    }
    request.push_str("Connection: close\r\n\r\n");
    request
}

/// Build TLS client configuration.
///
/// With `ca_path`: trust only the specified CA certificate.
/// Without: disable certificate verification (for test environments).
fn build_tls_config(ca_path: Option<&str>) -> rustls::ClientConfig {
    ca_path.map_or_else(
        || {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        },
        |ca_path| {
            let pem = std::fs::read_to_string(ca_path).unwrap_or_else(|e| {
                eprintln!("Failed to read CA cert {ca_path}: {e}");
                std::process::exit(1);
            });
            let mut store = rustls::RootCertStore::empty();
            let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| {
                    eprintln!("Failed to parse CA cert PEM: {e}");
                    std::process::exit(1);
                });
            for cert in certs {
                store.add(cert).unwrap_or_else(|e| {
                    eprintln!("Failed to add CA cert: {e}");
                    std::process::exit(1);
                });
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(store)
                .with_no_client_auth()
        },
    )
}

/// Parse an HTTPS URL into (host, port, request-target).
///
/// Returns the bare host (no brackets for IPv6), port number, and the
/// request-target path including query string but excluding fragment.
fn parse_url(url: &str) -> (String, u16, String) {
    let without_scheme = url.strip_prefix("https://").unwrap_or_else(|| {
        eprintln!("URL must start with https://");
        std::process::exit(1);
    });

    // Split authority from path/query/fragment.
    // Authority ends at the first '/', '?', or '#'.
    let (host_port, rest) = without_scheme
        .find(&['/', '?', '#'][..])
        .map_or((without_scheme, ""), |i| {
            (&without_scheme[..i], &without_scheme[i..])
        });

    // Build request-target: ensure it starts with '/', strip fragment
    let path = if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('/') {
        // Normal path — strip fragment (# and everything after)
        rest.find('#')
            .map_or_else(|| rest.to_string(), |i| rest[..i].to_string())
    } else if rest.starts_with('?') {
        // Query without path — prepend '/', strip fragment
        let without_frag = rest.find('#').map_or(rest, |i| &rest[..i]);
        format!("/{without_frag}")
    } else {
        // Starts with '#' — fragment only, not sent to server
        "/".to_string()
    };

    // Parse host and port, handling IPv6 bracket notation
    let (host, port) = if host_port.starts_with('[') {
        // IPv6: [addr] or [addr]:port
        let Some(bracket_end) = host_port.find(']') else {
            eprintln!("Invalid IPv6 URL: missing closing ']'");
            std::process::exit(1);
        };
        let bare_ip = &host_port[1..bracket_end];
        let after_bracket = &host_port[bracket_end + 1..];
        let port = after_bracket.strip_prefix(':').map_or(443, |port_str| {
            port_str.parse::<u16>().unwrap_or_else(|e| {
                eprintln!("Invalid port '{port_str}': {e}");
                std::process::exit(1);
            })
        });
        (bare_ip.to_string(), port)
    } else {
        // IPv4 or hostname
        host_port.rfind(':').map_or_else(
            || (host_port.to_string(), 443_u16),
            |i| {
                let port_str = &host_port[i + 1..];
                let port: u16 = port_str.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid port '{port_str}': {e}");
                    std::process::exit(1);
                });
                (host_port[..i].to_string(), port)
            },
        )
    };

    (host, port, path)
}

/// Build the Host header value per RFC 7230 §5.4.
///
/// Includes port only when non-default (not 443 for HTTPS).
/// Brackets IPv6 addresses.
fn build_host_header(host: &str, port: u16) -> String {
    let is_ipv6 = host.contains(':');
    match (is_ipv6, port) {
        (true, 443) => format!("[{host}]"),
        (true, _) => format!("[{host}]:{port}"),
        (false, 443) => host.to_string(),
        (false, _) => format!("{host}:{port}"),
    }
}

/// Certificate verifier that accepts everything (for --no-check-certificate).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    // =========================================================================
    // parse_url
    // =========================================================================

    #[test]
    fn test_parse_url_simple() {
        assert_eq!(
            parse_url("https://example.com"),
            ("example.com".into(), 443, "/".into())
        );
    }

    #[test]
    fn test_parse_url_with_path() {
        assert_eq!(
            parse_url("https://example.com/path"),
            ("example.com".into(), 443, "/path".into())
        );
    }

    #[test]
    fn test_parse_url_with_port() {
        assert_eq!(
            parse_url("https://example.com:8443"),
            ("example.com".into(), 8443, "/".into())
        );
    }

    #[test]
    fn test_parse_url_with_port_and_path() {
        assert_eq!(
            parse_url("https://example.com:8443/path/to"),
            ("example.com".into(), 8443, "/path/to".into())
        );
    }

    #[test]
    fn test_parse_url_query_without_path() {
        assert_eq!(
            parse_url("https://example.com?x=1"),
            ("example.com".into(), 443, "/?x=1".into())
        );
    }

    #[test]
    fn test_parse_url_query_multiple_params() {
        assert_eq!(
            parse_url("https://example.com?x=1&y=2"),
            ("example.com".into(), 443, "/?x=1&y=2".into())
        );
    }

    #[test]
    fn test_parse_url_fragment_only() {
        assert_eq!(
            parse_url("https://example.com#frag"),
            ("example.com".into(), 443, "/".into())
        );
    }

    #[test]
    fn test_parse_url_path_query_fragment() {
        assert_eq!(
            parse_url("https://example.com/path?q=1#frag"),
            ("example.com".into(), 443, "/path?q=1".into())
        );
    }

    #[test]
    fn test_parse_url_ipv6_with_port() {
        assert_eq!(
            parse_url("https://[::1]:8443/path"),
            ("::1".into(), 8443, "/path".into())
        );
    }

    #[test]
    fn test_parse_url_ipv6_no_port() {
        assert_eq!(
            parse_url("https://[::1]/path"),
            ("::1".into(), 443, "/path".into())
        );
    }

    #[test]
    fn test_parse_url_ipv6_full_address() {
        assert_eq!(
            parse_url("https://[2001:db8::1]:443/"),
            ("2001:db8::1".into(), 443, "/".into())
        );
    }

    #[test]
    fn test_parse_url_trailing_slash() {
        assert_eq!(
            parse_url("https://example.com/"),
            ("example.com".into(), 443, "/".into())
        );
    }

    // =========================================================================
    // build_host_header
    // =========================================================================

    #[test]
    fn test_host_header_default_port() {
        assert_eq!(build_host_header("example.com", 443), "example.com");
    }

    #[test]
    fn test_host_header_non_default_port() {
        assert_eq!(build_host_header("example.com", 8443), "example.com:8443");
    }

    #[test]
    fn test_host_header_ipv6_default_port() {
        assert_eq!(build_host_header("::1", 443), "[::1]");
    }

    #[test]
    fn test_host_header_ipv6_non_default_port() {
        assert_eq!(build_host_header("::1", 8443), "[::1]:8443");
    }
}
