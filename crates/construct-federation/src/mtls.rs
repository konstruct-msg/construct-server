use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::pem::PemObject;

/// Configuration for mTLS federation
#[derive(Clone, Debug)]
pub struct MtlsConfig {
    pub required: bool,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub verify_server_cert: bool,
    pub pinned_certs: HashMap<String, String>,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            required: false,
            client_cert_path: None,
            client_key_path: None,
            verify_server_cert: true,
            pinned_certs: HashMap::new(),
        }
    }
}

/// Trust store for federation partners.
///
/// Stores pinned + TOFU-learned certificate fingerprints.
pub struct FederationTrustStore {
    trusted_fingerprints: RwLock<HashMap<String, TrustedCert>>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct TrustedCert {
    fingerprint: String,
    first_seen: std::time::Instant,
    last_verified: std::time::Instant,
}

impl FederationTrustStore {
    pub fn new() -> Self {
        Self {
            trusted_fingerprints: RwLock::new(HashMap::new()),
        }
    }

    pub fn trust_fingerprint(&self, domain: &str, fingerprint: &str) {
        let mut store = self.trusted_fingerprints.write().unwrap_or_else(|e| {
            panic!("Failed to acquire write lock on trust store: {e}");
        });
        store.insert(
            domain.to_string(),
            TrustedCert {
                fingerprint: fingerprint.to_string(),
                first_seen: std::time::Instant::now(),
                last_verified: std::time::Instant::now(),
            },
        );
    }

    pub fn is_trusted(&self, domain: &str, fingerprint: &str) -> bool {
        let is_trusted = {
            let store = match self.trusted_fingerprints.read() {
                Ok(store) => store,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to acquire read lock on trust store");
                    return false;
                }
            };
            store
                .get(domain)
                .is_some_and(|trusted| trusted.fingerprint == fingerprint)
        };

        if is_trusted
            && let Ok(mut store) = self.trusted_fingerprints.write()
            && let Some(trusted) = store.get_mut(domain)
        {
            trusted.last_verified = std::time::Instant::now();
        }

        is_trusted
    }

    pub fn get_trusted_fingerprint(&self, domain: &str) -> Option<String> {
        let store = match self.trusted_fingerprints.read() {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(error = %e, "Failed to acquire read lock on trust store");
                return None;
            }
        };
        store.get(domain).map(|t| t.fingerprint.clone())
    }

    pub fn trust_on_first_use(&self, domain: &str, fingerprint: &str) -> bool {
        let mut store = match self.trusted_fingerprints.write() {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(error = %e, "Failed to acquire write lock on trust store");
                return false;
            }
        };

        if let Some(existing) = store.get(domain) {
            existing.fingerprint == fingerprint
        } else {
            tracing::info!(
                domain = %domain,
                fingerprint = %fingerprint,
                "TOFU: Trusting new federation partner certificate"
            );
            store.insert(
                domain.to_string(),
                TrustedCert {
                    fingerprint: fingerprint.to_string(),
                    first_seen: std::time::Instant::now(),
                    last_verified: std::time::Instant::now(),
                },
            );
            true
        }
    }
}

impl Default for FederationTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate SHA-256 fingerprint of a certificate (colon-separated hex).
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(cert_der);
    hash.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build a [`rustls::ClientConfig`] with a custom [`PinnedCertVerifier`] that
/// enforces certificate fingerprint pinning at the TLS handshake level.
///
/// * `trust_store` — stores pinned + TOFU-learned fingerprints.
/// * `mtls_config` — controls required/verify/client-certificate paths.
pub fn build_rustls_client_config(
    trust_store: Arc<FederationTrustStore>,
    mtls_config: &MtlsConfig,
) -> Result<rustls::ClientConfig, anyhow::Error> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .expect("default crypto provider installed (by reqwest)");

    let verifier = Arc::new(PinnedCertVerifier {
        trust_store,
        required: mtls_config.required,
        verify_server_cert: mtls_config.verify_server_cert,
        signature_algorithms: provider.signature_verification_algorithms,
    });

    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let config = if let (Some(cert_path), Some(key_path)) =
        (&mtls_config.client_cert_path, &mtls_config.client_key_path)
    {
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_file_iter(cert_path)
                .map_err(|e| anyhow::anyhow!("failed to read client cert at {cert_path}: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("failed to parse client cert at {cert_path}: {e}"))?;
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key_path)
            .map_err(|e| anyhow::anyhow!("failed to read client key at {key_path}: {e}"))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("failed to set client auth: {e}"))?
    } else {
        builder.with_no_client_auth()
    };

    tracing::debug!("Built rustls ClientConfig with custom PinnedCertVerifier");
    Ok(config)
}

/// A [`rustls::verify::ServerCertVerifier`] that enforces certificate fingerprint
/// pinning instead of (or in addition to) standard CA chain verification.
struct PinnedCertVerifier {
    trust_store: Arc<FederationTrustStore>,
    required: bool,
    verify_server_cert: bool,
    signature_algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("required", &self.required)
            .field("verify_server_cert", &self.verify_server_cert)
            .field(
                "signature_algorithms",
                &self.signature_algorithms.supported_schemes().len(),
            )
            .finish()
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let domain = match server_name {
            rustls_pki_types::ServerName::DnsName(dns) => dns.as_ref(),
            _ => {
                return Err(rustls::Error::General(
                    "unsupported server name type — only DNS names supported".into(),
                ));
            }
        };

        let fp = cert_fingerprint(end_entity);

        // Fast path: already pinned and matching
        if self.trust_store.is_trusted(domain, &fp) {
            return Ok(ServerCertVerified::assertion());
        }

        // Not trusted by existing pin — decide what to do
        let existing = self.trust_store.get_trusted_fingerprint(domain);

        match existing {
            Some(expected) => Err(rustls::Error::General(format!(
                "Certificate pinning failure for {domain}: \
                 expected {expected}, got {fp}"
            ))),
            None => {
                if self.required {
                    Err(rustls::Error::General(format!(
                        "Pinned certificate required for {domain} but none configured"
                    )))
                } else if self.verify_server_cert {
                    // TOFU — trust this cert on first use
                    if self.trust_store.trust_on_first_use(domain, &fp) {
                        tracing::info!(
                            domain = %domain,
                            fingerprint = %fp,
                            "TOFU: trusted new federation partner certificate"
                        );
                        Ok(ServerCertVerified::assertion())
                    } else {
                        Err(rustls::Error::General(format!(
                            "TOFU rejected for {domain}"
                        )))
                    }
                } else {
                    // Danger mode — accept any cert, just log
                    tracing::warn!(
                        domain = %domain,
                        fingerprint = %fp,
                        "TLS verification disabled — accepting any certificate"
                    );
                    Ok(ServerCertVerified::assertion())
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.signature_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_store_tofu() {
        let store = FederationTrustStore::new();

        assert!(store.trust_on_first_use("example.com", "AA:BB:CC"));
        assert!(store.is_trusted("example.com", "AA:BB:CC"));

        assert!(store.trust_on_first_use("example.com", "AA:BB:CC"));

        assert!(!store.trust_on_first_use("example.com", "DD:EE:FF"));
        assert!(!store.is_trusted("example.com", "DD:EE:FF"));
    }

    #[test]
    fn test_fingerprint_calculation() {
        let cert_data = b"test certificate data";
        let fingerprint = cert_fingerprint(cert_data);

        assert!(fingerprint.contains(':'));
        assert_eq!(fingerprint.len(), 95);
    }
}
