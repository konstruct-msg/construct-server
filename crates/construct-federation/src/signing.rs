// ============================================================================
// Federation Signing - Server-to-Server Authentication
// ============================================================================
//
// Implements Ed25519 signing for S2S message authentication:
// - Server signs outgoing federated messages
// - Remote servers verify signatures via public key from .well-known/konstruct
//
// Security model:
// - Each instance has a unique Ed25519 key pair
// - Private key stored as SECRET (never exposed)
// - Public key published in .well-known/konstruct for verification
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
pub enum SigningError {
    InvalidKey(String),
    VerificationFailed,
    InvalidSignature(String),
    RemoteKeyFetch(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::InvalidKey(msg) => write!(f, "Invalid signing key: {}", msg),
            SigningError::VerificationFailed => write!(f, "Signature verification failed"),
            SigningError::InvalidSignature(msg) => write!(f, "Invalid signature format: {}", msg),
            SigningError::RemoteKeyFetch(msg) => {
                write!(f, "Failed to fetch remote public key: {}", msg)
            }
        }
    }
}

impl std::error::Error for SigningError {}

/// Server signing key manager
///
/// Handles Ed25519 key operations for federation authentication
pub struct ServerSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    instance_domain: String,
}

impl ServerSigner {
    /// Create a new server signer from a base64-encoded seed
    ///
    /// The seed should be 32 bytes, base64-encoded (from openssl rand -base64 32)
    pub fn from_seed_base64(seed_b64: &str, instance_domain: String) -> Result<Self, SigningError> {
        let seed_bytes = BASE64
            .decode(seed_b64.trim())
            .map_err(|e| SigningError::InvalidKey(format!("Invalid base64: {}", e)))?;

        if seed_bytes.len() != 32 {
            return Err(SigningError::InvalidKey(format!(
                "Seed must be 32 bytes, got {}",
                seed_bytes.len()
            )));
        }

        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| SigningError::InvalidKey("Failed to convert seed".to_string()))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        tracing::info!(
            instance = %instance_domain,
            public_key = %BASE64.encode(verifying_key.as_bytes()),
            "Server signing key initialized"
        );

        Ok(Self {
            signing_key,
            verifying_key,
            instance_domain,
        })
    }

    /// Get the public key as base64 for .well-known/konstruct
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.verifying_key.as_bytes())
    }

    /// Get the instance domain
    pub fn instance_domain(&self) -> &str {
        &self.instance_domain
    }

    /// Sign a federated message envelope
    ///
    /// Creates a signature over the canonical representation of the message
    pub fn sign_message(&self, envelope: &FederatedEnvelope) -> String {
        let canonical = envelope.canonical_bytes();
        let signature = self.signing_key.sign(&canonical);
        BASE64.encode(signature.to_bytes())
    }

    /// Sign arbitrary bytes and return the raw Ed25519 signature (64 bytes)
    ///
    /// Used for SenderCertificate signing where the payload is
    /// a canonical concatenation of certificate fields.
    pub fn sign_bytes(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature from a remote server
    ///
    /// Uses the provided public key to verify the signature
    pub fn verify_signature(
        public_key_b64: &str,
        envelope: &FederatedEnvelope,
        signature_b64: &str,
    ) -> Result<(), SigningError> {
        // Decode public key
        let public_key_bytes = BASE64
            .decode(public_key_b64)
            .map_err(|e| SigningError::InvalidKey(format!("Invalid public key base64: {}", e)))?;

        if public_key_bytes.len() != 32 {
            return Err(SigningError::InvalidKey(format!(
                "Public key must be 32 bytes, got {}",
                public_key_bytes.len()
            )));
        }

        let public_key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| SigningError::InvalidKey("Failed to convert public key".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| SigningError::InvalidKey(format!("Invalid Ed25519 public key: {}", e)))?;

        // Decode signature
        let signature_bytes = BASE64.decode(signature_b64).map_err(|e| {
            SigningError::InvalidSignature(format!("Invalid signature base64: {}", e))
        })?;

        if signature_bytes.len() != 64 {
            return Err(SigningError::InvalidSignature(format!(
                "Signature must be 64 bytes, got {}",
                signature_bytes.len()
            )));
        }

        let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            SigningError::InvalidSignature("Failed to convert signature".to_string())
        })?;

        let signature = Signature::from_bytes(&signature_array);

        // Verify
        let canonical = envelope.canonical_bytes();
        verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| SigningError::VerificationFailed)?;

        Ok(())
    }
}

/// Federated message envelope for signing/verification
///
/// Contains all fields that are signed to prevent tampering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedEnvelope {
    /// Message ID (UUID)
    pub message_id: String,

    /// Sender address (alice@remote.konstruct.cc)
    pub from: String,

    /// Recipient address (bob@eu.konstruct.cc)
    pub to: String,

    /// Origin server domain (who is sending this S2S request)
    pub origin_server: String,

    /// Destination server domain
    pub destination_server: String,

    /// Message timestamp (Unix seconds)
    pub timestamp: u64,

    /// Hash of the encrypted payload (for integrity)
    pub payload_hash: String,
}

impl FederatedEnvelope {
    /// Create canonical bytes for signing
    ///
    /// Format: message_id || from || to || origin || dest || timestamp || payload_hash
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let canonical_string = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.message_id,
            self.from,
            self.to,
            self.origin_server,
            self.destination_server,
            self.timestamp,
            self.payload_hash
        );
        canonical_string.into_bytes()
    }

    /// Create payload hash from ciphertext
    pub fn hash_payload(ciphertext: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext.as_bytes());
        let result = hasher.finalize();
        BASE64.encode(result)
    }
}

/// Cache for remote server public keys
///
/// Caches public keys fetched from .well-known/konstruct
/// to avoid repeated HTTP requests
pub struct PublicKeyCache {
    cache: std::sync::RwLock<std::collections::HashMap<String, CachedPublicKey>>,
    http_client: reqwest::Client,
}

#[derive(Clone)]
struct CachedPublicKey {
    public_key: String,
    fetched_at: std::time::Instant,
}

impl PublicKeyCache {
    /// Create a new public key cache
    pub fn new() -> Self {
        Self {
            cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "Failed to create HTTP client for public key cache");
                    panic!("Failed to create HTTP client: {}. This is a critical error and the application cannot continue.", e);
                }),
        }
    }

    /// Get public key for a domain, fetching if not cached or expired
    ///
    /// Cache TTL: 1 hour
    pub async fn get_public_key(&self, domain: &str) -> Result<String, SigningError> {
        // Check cache first
        {
            match self.cache.read() {
                Ok(cache) => {
                    if let Some(cached) = cache.get(domain)
                        && cached.fetched_at.elapsed() < std::time::Duration::from_secs(3600)
                    {
                        return Ok(cached.public_key.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to acquire read lock on public key cache, will fetch from remote");
                }
            }
        }

        // Fetch from remote
        let public_key = self.fetch_public_key(domain).await?;

        // Update cache
        match self.cache.write() {
            Ok(mut cache) => {
                cache.insert(
                    domain.to_string(),
                    CachedPublicKey {
                        public_key: public_key.clone(),
                        fetched_at: std::time::Instant::now(),
                    },
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to update public key cache (non-critical)");
                // Continue anyway - we have the key
            }
        }

        Ok(public_key)
    }

    /// Fetch public key from .well-known/konstruct
    async fn fetch_public_key(&self, domain: &str) -> Result<String, SigningError> {
        let url = format!("https://{}/.well-known/konstruct", domain);

        tracing::debug!(domain = %domain, url = %url, "Fetching public key from remote server");

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| SigningError::RemoteKeyFetch(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(SigningError::RemoteKeyFetch(format!(
                "HTTP {} from {}",
                response.status(),
                domain
            )));
        }

        #[derive(Deserialize)]
        struct WellKnownResponse {
            public_key: Option<String>,
            federation: Option<FederationInfo>,
        }

        #[derive(Deserialize)]
        struct FederationInfo {
            public_key: Option<String>,
        }

        let body: WellKnownResponse = response
            .json()
            .await
            .map_err(|e| SigningError::RemoteKeyFetch(format!("Failed to parse JSON: {}", e)))?;

        // Try top-level public_key first, then federation.public_key
        let public_key = body
            .public_key
            .or_else(|| body.federation.and_then(|f| f.public_key))
            .ok_or_else(|| {
                SigningError::RemoteKeyFetch(format!(
                    "No public_key found in .well-known/konstruct for {}",
                    domain
                ))
            })?;

        tracing::info!(domain = %domain, "Successfully fetched public key from remote server");

        Ok(public_key)
    }

    /// Clear the cache (for testing or key rotation)
    #[allow(dead_code)]
    pub fn clear(&self) {
        match self.cache.write() {
            Ok(mut cache) => {
                cache.clear();
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to clear public key cache");
            }
        }
    }
}

impl Default for PublicKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_signer_from_seed() {
        // Generate a test seed (in production, use: openssl rand -base64 32)
        // This is a valid 32-byte seed: "0123456789abcdef0123456789abcdef" encoded in base64
        let seed_b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="; // 32 bytes base64

        let signer = ServerSigner::from_seed_base64(seed_b64, "test.konstruct.cc".to_string());
        assert!(signer.is_ok());

        let signer = signer.unwrap();
        assert!(!signer.public_key_base64().is_empty());
        assert_eq!(signer.instance_domain(), "test.konstruct.cc");
    }

    #[test]
    fn test_sign_and_verify() {
        // This is a valid 32-byte seed: "0123456789abcdef0123456789abcdef" encoded in base64
        let seed_b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let signer =
            ServerSigner::from_seed_base64(seed_b64, "origin.konstruct.cc".to_string()).unwrap();

        let envelope = FederatedEnvelope {
            message_id: "test-message-id".to_string(),
            from: "alice@origin.konstruct.cc".to_string(),
            to: "bob@dest.konstruct.cc".to_string(),
            origin_server: "origin.konstruct.cc".to_string(),
            destination_server: "dest.konstruct.cc".to_string(),
            timestamp: 1704067200,
            payload_hash: FederatedEnvelope::hash_payload("encrypted-content"),
        };

        // Sign
        let signature = signer.sign_message(&envelope);
        assert!(!signature.is_empty());

        // Verify with correct public key
        let public_key = signer.public_key_base64();
        let result = ServerSigner::verify_signature(&public_key, &envelope, &signature);
        assert!(result.is_ok());

        // Verify fails with wrong public key
        // This is a valid 32-byte seed: "fedcba9876543210fedcba9876543210" encoded in base64
        let wrong_seed = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
        let wrong_signer =
            ServerSigner::from_seed_base64(wrong_seed, "other.konstruct.cc".to_string()).unwrap();
        let result = ServerSigner::verify_signature(
            &wrong_signer.public_key_base64(),
            &envelope,
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_canonical_bytes() {
        let envelope = FederatedEnvelope {
            message_id: "msg-123".to_string(),
            from: "alice@a.cc".to_string(),
            to: "bob@b.cc".to_string(),
            origin_server: "a.cc".to_string(),
            destination_server: "b.cc".to_string(),
            timestamp: 1000,
            payload_hash: "hash123".to_string(),
        };

        let canonical = envelope.canonical_bytes();
        let expected = "msg-123:alice@a.cc:bob@b.cc:a.cc:b.cc:1000:hash123";
        assert_eq!(canonical, expected.as_bytes());
    }

    #[test]
    fn test_payload_hash() {
        let hash = FederatedEnvelope::hash_payload("test content");
        assert!(!hash.is_empty());

        // Same input = same hash
        let hash2 = FederatedEnvelope::hash_payload("test content");
        assert_eq!(hash, hash2);

        // Different input = different hash
        let hash3 = FederatedEnvelope::hash_payload("different content");
        assert_ne!(hash, hash3);
    }
}
