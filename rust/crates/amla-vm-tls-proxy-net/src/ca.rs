// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Certificate Authority — generates a self-signed CA and per-domain leaf certs.
//!
//! The CA is created once at startup. Leaf certificates are generated on demand
//! (one per unique hostname) and cached with bounded FIFO eviction.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};

/// Maximum number of cached leaf certificates before FIFO eviction kicks in.
const MAX_LEAF_CACHE: usize = 256;

/// How long a cached leaf is considered fresh before we regenerate it.
///
/// rcgen's default leaf validity is 7 days from the moment `generate_leaf`
/// runs. Refreshing every 6 hours leaves a ~6.75-day margin, so a leaf pulled
/// from the cache can never be expired when it reaches rustls — a long-running
/// proxy that generated a cert on day 0 would otherwise still be handing it
/// out on day 8.
const LEAF_CACHE_TTL: Duration = Duration::from_hours(6);

/// Errors from CA operations.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("private key DER conversion failed")]
    KeyConversion,
    #[error("leaf cache lock poisoned")]
    LockPoisoned,
    #[error("TLS server config construction failed: {0}")]
    TlsConfig(String),
}

/// Build a `rustls::ServerConfig` that presents `leaf` as the server cert,
/// with `ca`'s cert chained for clients that want the full trust path.
///
/// `alpn_protocols` is advertised in the `ServerHello`. The MITM task
/// always passes `[b"h2", b"http/1.1"]` in that order so the guest can
/// pick h2.
pub fn build_guest_tls_config(
    leaf: &CachedLeafCert,
    ca: &CertificateAuthority,
    alpn_protocols: &[Vec<u8>],
) -> Result<rustls::ServerConfig, CaError> {
    let cert_chain = vec![leaf.cert_der.clone(), ca.ca_cert_der.clone()];
    let key = leaf.key_der.clone_key();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| CaError::TlsConfig(e.to_string()))?;
    config.alpn_protocols = alpn_protocols.to_vec();
    Ok(config)
}

/// A MITM Certificate Authority.
///
/// Thread-safe: the leaf cache uses `RwLock` for concurrent reads.
///
/// To inject this CA into a guest trust store, use one of:
/// - `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` env vars pointing to `ca_cert_pem()` output
/// - Copy PEM to `/etc/ssl/certs/` and run `update-ca-certificates`
pub struct CertificateAuthority {
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
    ca_cert_der: rustls::pki_types::CertificateDer<'static>,
    ca_cert_pem: String,
    leaf_cache: RwLock<LeafCache>,
}

struct LeafCache {
    entries: HashMap<String, LeafEntry>,
    /// Insertion order for FIFO eviction — oldest at front, newest at back.
    order: VecDeque<String>,
}

struct LeafEntry {
    leaf: Arc<CachedLeafCert>,
    inserted_at: Instant,
}

/// A cached leaf certificate (cert chain + private key in DER form).
///
/// Fields are `pub(crate)` — construction is restricted to the CA module so
/// the invariant "cert and key form a valid keypair signed by this CA" can
/// only be violated via unsafe. External callers access the parts via the
/// read-only [`Self::cert_der`] / [`Self::key_der`] accessors.
pub struct CachedLeafCert {
    pub(crate) cert_der: rustls::pki_types::CertificateDer<'static>,
    pub(crate) key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

impl CachedLeafCert {
    /// The DER-encoded leaf certificate (not the chain — callers typically
    /// prepend the CA cert via [`CertificateAuthority::ca_cert_der`] to form
    /// a chain for `rustls::ConfigBuilder::with_single_cert`).
    #[must_use]
    pub const fn cert_der(&self) -> &rustls::pki_types::CertificateDer<'static> {
        &self.cert_der
    }

    /// The DER-encoded leaf private key. Uses `PrivateKeyDer::clone_key`
    /// when callers need an owned copy (the type doesn't implement `Clone`
    /// directly because some inner key representations don't).
    #[must_use]
    pub const fn key_der(&self) -> &rustls::pki_types::PrivateKeyDer<'static> {
        &self.key_der
    }
}

impl CertificateAuthority {
    /// Generate a new self-signed CA.
    ///
    /// Uses an ECDSA P-256 key (see `PKCS_ECDSA_P256_SHA256` below). P-256 is
    /// universally supported by modern TLS stacks, keeps cert sizes small, and
    /// signing is cheap — leaf certs are generated on-demand per hostname.
    pub fn new() -> Result<Self, CaError> {
        // Ensure ring crypto provider is installed. When multiple providers
        // are enabled via Cargo feature unification (e.g., ring + aws-lc-rs),
        // rustls cannot auto-detect. Ignore AlreadyInstalled errors.
        crate::install_crypto_provider();

        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "amla MITM CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "amla");
        // pathLenConstraint=0: this CA may sign end-entity certs only, never
        // sub-CAs. Limits blast radius if the private key leaks — a stolen CA
        // could still MITM hostnames, but cannot mint sub-CAs to delegate that
        // capability elsewhere.
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca_cert_der = rustls::pki_types::CertificateDer::from(ca_cert.der().to_vec());
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_key,
            ca_cert,
            ca_cert_der,
            ca_cert_pem,
            leaf_cache: RwLock::new(LeafCache {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Returns the CA certificate in DER form (for guest trust store injection).
    pub const fn ca_cert_der(&self) -> &rustls::pki_types::CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Returns the CA certificate in PEM form (for `SSL_CERT_FILE` or `update-ca-certificates`).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get or generate a leaf certificate for the given hostname.
    ///
    /// Returned cert is signed by this CA. Cached for future use; entries
    /// older than `LEAF_CACHE_TTL` are regenerated so we never hand out a
    /// leaf that's close to (or past) its own `notAfter`.
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn get_leaf_cert(&self, hostname: &str) -> Result<Arc<CachedLeafCert>, CaError> {
        // Fast path: read lock. Only a fresh entry is a hit — a stale one
        // falls through to the slow path so we regenerate it.
        {
            let cache = self.leaf_cache.read().map_err(|_| CaError::LockPoisoned)?;
            if let Some(entry) = cache.entries.get(hostname)
                && entry.inserted_at.elapsed() < LEAF_CACHE_TTL
            {
                return Ok(Arc::clone(&entry.leaf));
            }
        }

        // Slow path: generate + write lock
        let leaf = self.generate_leaf(hostname)?;
        let leaf = Arc::new(leaf);

        let mut cache = self.leaf_cache.write().map_err(|_| CaError::LockPoisoned)?;

        // Double-check (another thread may have generated it). Again, only a
        // fresh entry wins — a stale one we raced to regenerate gets replaced.
        if let Some(entry) = cache.entries.get(hostname)
            && entry.inserted_at.elapsed() < LEAF_CACHE_TTL
        {
            return Ok(Arc::clone(&entry.leaf));
        }

        // FIFO eviction — oldest entries are at the front
        while cache.order.len() >= MAX_LEAF_CACHE {
            if let Some(oldest) = cache.order.pop_front() {
                cache.entries.remove(&oldest);
            }
        }

        let was_replaced = cache
            .entries
            .insert(
                hostname.to_string(),
                LeafEntry {
                    leaf: Arc::clone(&leaf),
                    inserted_at: Instant::now(),
                },
            )
            .is_some();
        // On a stale-refresh we already had an order-queue slot for this
        // hostname; pushing again would double-count it toward MAX_LEAF_CACHE
        // and eventually evict a different hostname's still-live entry.
        if !was_replaced {
            cache.order.push_back(hostname.to_string());
        }

        Ok(leaf)
    }

    /// Generate a leaf certificate for the given hostname, signed by our CA.
    fn generate_leaf(&self, hostname: &str) -> Result<CachedLeafCert, CaError> {
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        let san = if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            // IP address → IP SAN
            vec![rcgen::SanType::IpAddress(ip)]
        } else {
            // DNS name → DNS SAN
            let ia5: rcgen::Ia5String = hostname.try_into()?;
            vec![rcgen::SanType::DnsName(ia5)]
        };

        let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, hostname);
        leaf_params.subject_alt_names = san;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_cert = leaf_params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;

        let cert_der = rustls::pki_types::CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|_| CaError::KeyConversion)?;

        Ok(CachedLeafCert { cert_der, key_der })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared CA instance — RSA key generation in debug builds takes ~1.3s,
    /// so sharing one CA across all tests saves ~17s (14 tests × 1.3s).
    ///
    /// Tests that need a fresh CA (eviction tests) create their own.
    static SHARED_CA: std::sync::LazyLock<CertificateAuthority> =
        std::sync::LazyLock::new(|| CertificateAuthority::new().unwrap());

    #[test]
    fn ca_generation() {
        let ca = &*SHARED_CA;
        assert!(!ca.ca_cert_der().is_empty());
    }

    #[test]
    fn leaf_cert_generation() {
        let ca = &*SHARED_CA;
        let leaf = ca.get_leaf_cert("api.openai.com").unwrap();
        assert!(!leaf.cert_der.is_empty());
    }

    #[test]
    fn leaf_cert_caching() {
        let ca = &*SHARED_CA;
        let leaf1 = ca.get_leaf_cert("caching-test.openai.com").unwrap();
        let leaf2 = ca.get_leaf_cert("caching-test.openai.com").unwrap();
        // Same Arc (pointer equality)
        assert!(Arc::ptr_eq(&leaf1, &leaf2));
    }

    #[test]
    fn leaf_cert_for_ip() {
        let ca = &*SHARED_CA;
        let leaf = ca.get_leaf_cert("127.0.0.1").unwrap();
        assert!(!leaf.cert_der.is_empty());
    }

    /// Build a dummy leaf cert for pre-filling the cache without RSA keygen.
    fn dummy_leaf(ca: &CertificateAuthority) -> Arc<CachedLeafCert> {
        let key_der_vec = ca.ca_key.serialize_der();
        Arc::new(CachedLeafCert {
            cert_der: rustls::pki_types::CertificateDer::from(vec![0u8]),
            key_der: rustls::pki_types::PrivateKeyDer::try_from(key_der_vec.as_slice())
                .unwrap()
                .clone_key(),
        })
    }

    fn prefill_entry(dummy: &Arc<CachedLeafCert>) -> LeafEntry {
        LeafEntry {
            leaf: Arc::clone(dummy),
            inserted_at: Instant::now(),
        }
    }

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn fifo_eviction() {
        // Fresh CA needed — eviction test fills cache beyond capacity.
        // Pre-fill directly via internal API to avoid RSA key generation
        // for 256+ leaf certs (would take ~18s in debug builds).
        let ca = CertificateAuthority::new().unwrap();
        let dummy = dummy_leaf(&ca);
        {
            let mut cache = ca.leaf_cache.write().unwrap();
            for i in 0..MAX_LEAF_CACHE + 10 {
                let name = format!("host{i}.example.com");
                cache.order.push_back(name.clone());
                cache.entries.insert(name, prefill_entry(&dummy));
            }
        }
        // Trigger eviction by requesting a new cert (forces the slow path).
        ca.get_leaf_cert("trigger-eviction.example.com").unwrap();
        let cache = ca.leaf_cache.read().unwrap();
        assert!(cache.entries.len() <= MAX_LEAF_CACHE);
    }

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn fifo_eviction_removes_oldest_entries() {
        // Fresh CA needed — eviction test fills cache to capacity.
        // Pre-fill via internal API to avoid generating 256 RSA keys.
        let ca = CertificateAuthority::new().unwrap();
        let dummy = dummy_leaf(&ca);
        {
            let mut cache = ca.leaf_cache.write().unwrap();
            for i in 0..MAX_LEAF_CACHE {
                let name = format!("host{i}.example.com");
                cache.order.push_back(name.clone());
                cache.entries.insert(name, prefill_entry(&dummy));
            }
        }
        // Adding one more triggers eviction of the oldest (host0).
        ca.get_leaf_cert("new.example.com").unwrap();

        let cache = ca.leaf_cache.read().unwrap();
        assert!(
            !cache.entries.contains_key("host0.example.com"),
            "oldest entry should have been evicted"
        );
        assert!(
            cache.entries.contains_key("host1.example.com"),
            "second-oldest should still be present"
        );
        assert!(
            cache.entries.contains_key("new.example.com"),
            "newly inserted entry should be present"
        );
    }

    #[test]
    fn leaf_cert_for_ipv6() {
        let ca = &*SHARED_CA;
        let leaf = ca.get_leaf_cert("::1").unwrap();
        assert!(!leaf.cert_der.is_empty());
        assert!(!leaf.key_der.secret_der().is_empty());
    }

    #[test]
    fn leaf_cert_has_key() {
        let ca = &*SHARED_CA;
        let leaf = ca.get_leaf_cert("leaf-key-test.example.com").unwrap();
        assert!(!leaf.key_der.secret_der().is_empty());
    }

    #[test]
    fn different_hostnames_get_different_certs() {
        let ca = &*SHARED_CA;
        let leaf_a = ca.get_leaf_cert("diff-a.example.com").unwrap();
        let leaf_b = ca.get_leaf_cert("diff-b.example.com").unwrap();
        assert!(!Arc::ptr_eq(&leaf_a, &leaf_b));
        assert_ne!(leaf_a.cert_der, leaf_b.cert_der);
    }

    /// Verify the generated leaf cert is actually trusted by a rustls client
    /// configured with our CA cert as a trust anchor.
    #[test]
    fn leaf_cert_validates_against_ca() {
        let ca = &*SHARED_CA;
        let leaf = ca.get_leaf_cert("test.example.com").unwrap();

        // Build a root cert store with our CA
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca.ca_cert_der().clone()).unwrap();

        // Build a server config with the leaf cert
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.cert_der.clone()], leaf.key_der.clone_key())
            .unwrap();

        // Build a client config trusting our CA
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Attempt a handshake — if the cert chain is invalid, this will fail.
        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();

        // Drive one round of the handshake to verify cert validation passes.
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut std::io::Cursor::new(&buf)).unwrap();
        server.process_new_packets().unwrap();

        let mut buf2 = Vec::new();
        server.write_tls(&mut buf2).unwrap();
        client.read_tls(&mut std::io::Cursor::new(&buf2)).unwrap();
        // This is the key assertion — process_new_packets validates the cert chain.
        client.process_new_packets().unwrap();
    }

    /// Verify IP-based leaf certs validate when the client connects by IP.
    #[test]
    fn ip_leaf_cert_validates_against_ca() {
        let ca = &*SHARED_CA;
        let leaf = ca.get_leaf_cert("127.0.0.1").unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca.ca_cert_der().clone()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.cert_der.clone()], leaf.key_der.clone_key())
            .unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name: rustls::pki_types::ServerName<'_> =
            rustls::pki_types::IpAddr::from(std::net::Ipv4Addr::LOCALHOST).into();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();

        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut std::io::Cursor::new(&buf)).unwrap();
        server.process_new_packets().unwrap();

        let mut buf2 = Vec::new();
        server.write_tls(&mut buf2).unwrap();
        client.read_tls(&mut std::io::Cursor::new(&buf2)).unwrap();
        client.process_new_packets().unwrap();
    }

    // ── PEM output tests ────────────────────────────────────────────

    #[test]
    fn ca_cert_pem_format() {
        let ca = &*SHARED_CA;
        let pem = ca.ca_cert_pem();
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "PEM should start with header, got: {}",
            &pem[..pem.len().min(40)]
        );
        assert!(
            pem.trim_end().ends_with("-----END CERTIFICATE-----"),
            "PEM should end with footer"
        );
    }

    #[test]
    fn ca_cert_pem_decodes_to_matching_der() {
        use rustls::pki_types::pem::PemObject;
        let ca = &*SHARED_CA;
        let pem = ca.ca_cert_pem();

        let decoded_der = rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes())
            .expect("PEM should decode successfully");
        assert_eq!(
            decoded_der.as_ref(),
            ca.ca_cert_der().as_ref(),
            "PEM-decoded DER should match ca_cert_der()"
        );
    }

    #[test]
    fn ca_cert_not_regenerated_per_leaf() {
        let ca = &*SHARED_CA;
        let der_before = ca.ca_cert_der().clone();
        let pem_before = ca.ca_cert_pem().to_string();

        // Generate several leaf certs (unique names to avoid cache hits)
        ca.get_leaf_cert("noregen-a.example.com").unwrap();
        ca.get_leaf_cert("noregen-b.example.com").unwrap();
        ca.get_leaf_cert("noregen-c.example.com").unwrap();

        // CA cert should be identical (not regenerated)
        assert_eq!(ca.ca_cert_der(), &der_before);
        assert_eq!(ca.ca_cert_pem(), pem_before);
    }
}
