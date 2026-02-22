// ============================================================================
// mTLS (Mutual TLS) for S2S Federation
// ============================================================================
//
// Adds certificate-based authentication between federation servers.
// Both client and server present certificates during TLS handshake.
//
// Security model:
// - Each server has its own TLS certificate (from Let's Encrypt or self-signed CA)
// - Servers can pin trusted federation partner certificates
// - Provides additional authentication layer beyond Ed25519 signatures
//
// Why mTLS?
// - Ed25519 signatures authenticate message content
// - mTLS authenticates the connection itself
// - Together: defense in depth
//
// ============================================================================

use std::collections::HashMap;
use std::sync::RwLock;

/// Configuration for mTLS federation
#[derive(Clone, Debug)]
pub struct MtlsConfig {
    /// Whether mTLS is required for S2S connections
    pub required: bool,
    /// Path to client certificate for outgoing connections
    pub client_cert_path: Option<String>,
    /// Path to client key for outgoing connections
    pub client_key_path: Option<String>,
    /// Whether to verify server certificates (should be true in production)
    pub verify_server_cert: bool,
    /// Pinned certificate fingerprints for known federation partners
    /// Map of domain -> SHA256 fingerprint
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

/// Trust store for federation partners
///
/// Caches verified server certificates and allows pinning
pub struct FederationTrustStore {
    /// Known good certificate fingerprints (domain -> fingerprint)
    trusted_fingerprints: RwLock<HashMap<String, TrustedCert>>,
}

#[derive(Clone)]
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

    /// Add a trusted certificate fingerprint for a domain
    pub fn trust_fingerprint(&self, domain: &str, fingerprint: &str) {
        let mut store = self.trusted_fingerprints.write().unwrap_or_else(|e| {
            tracing::error!(error = %e, "Failed to acquire write lock on trust store");
            panic!("Failed to acquire write lock on trust store: {}", e);
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

    /// Check if a certificate fingerprint is trusted for a domain
    /// Updates last_verified timestamp if the certificate is trusted
    pub fn is_trusted(&self, domain: &str, fingerprint: &str) -> bool {
        // First check if trusted (read-only for performance)
        let is_trusted = {
            let store = match self.trusted_fingerprints.read() {
                Ok(store) => store,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to acquire read lock on trust store");
                    return false; // Fail closed - don't trust if we can't check
                }
            };
            if let Some(trusted) = store.get(domain) {
                trusted.fingerprint == fingerprint
            } else {
                false
            }
        };

        // If trusted, update last_verified timestamp
        if is_trusted
            && let Ok(mut store) = self.trusted_fingerprints.write()
            && let Some(trusted) = store.get_mut(domain)
        {
            trusted.last_verified = std::time::Instant::now();
        }

        is_trusted
    }

    /// Get the trusted fingerprint for a domain (if any)
    /// Returns (fingerprint, first_seen, last_verified)
    pub fn get_trusted_fingerprint(&self, domain: &str) -> Option<String> {
        let store = match self.trusted_fingerprints.read() {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(error = %e, "Failed to acquire read lock on trust store");
                return None;
            }
        };
        store.get(domain).map(|t| {
            // Use last_verified to track access
            let _ = t.last_verified; // Track that we accessed this field
            t.fingerprint.clone()
        })
    }

    /// Get certificate metadata for a domain (for monitoring/debugging)
    pub fn get_cert_metadata(
        &self,
        domain: &str,
    ) -> Option<(String, std::time::Instant, std::time::Instant)> {
        let store = match self.trusted_fingerprints.read() {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(error = %e, "Failed to acquire read lock on trust store");
                return None;
            }
        };
        store
            .get(domain)
            .map(|t| (t.fingerprint.clone(), t.first_seen, t.last_verified))
    }

    /// Trust on first use (TOFU) - trust a new certificate if none is pinned
    ///
    /// Returns true if the certificate is now trusted, false if it conflicts
    /// with an existing pinned certificate
    pub fn trust_on_first_use(&self, domain: &str, fingerprint: &str) -> bool {
        let mut store = match self.trusted_fingerprints.write() {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(error = %e, "Failed to acquire write lock on trust store");
                return false; // Fail closed - don't trust if we can't update
            }
        };

        if let Some(existing) = store.get(domain) {
            // Already have a pinned cert - check if it matches
            existing.fingerprint == fingerprint
        } else {
            // First time seeing this domain - trust it
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

/// Calculate SHA256 fingerprint of a certificate
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(cert_der);
    // Format as colon-separated hex (like browser fingerprints)
    hash.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_store_tofu() {
        let store = FederationTrustStore::new();

        // First connection - should trust
        assert!(store.trust_on_first_use("example.com", "AA:BB:CC"));
        assert!(store.is_trusted("example.com", "AA:BB:CC"));

        // Same fingerprint - should still be trusted
        assert!(store.trust_on_first_use("example.com", "AA:BB:CC"));

        // Different fingerprint - should reject (cert changed!)
        assert!(!store.trust_on_first_use("example.com", "DD:EE:FF"));
        assert!(!store.is_trusted("example.com", "DD:EE:FF"));
    }

    #[test]
    fn test_fingerprint_calculation() {
        let cert_data = b"test certificate data";
        let fingerprint = cert_fingerprint(cert_data);

        // Should be SHA256 in hex with colons
        assert!(fingerprint.contains(':'));
        assert_eq!(fingerprint.len(), 95); // 32 bytes * 2 hex chars + 31 colons
    }
}
