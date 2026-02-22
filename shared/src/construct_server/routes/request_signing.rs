// ============================================================================
// Request Signing - Client Request Authentication
// ============================================================================
//
// Implements Ed25519 request signing for critical operations (like Signal):
// - Client signs critical requests (key upload, account deletion) with their Ed25519 key
// - Server verifies signature using client's public key from key bundle
//
// Security model:
// - Uses client's master_identity_key (Ed25519) for signing
// - Canonical request format prevents tampering
// - Protects against request replay and tampering
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
pub enum RequestSigningError {
    MissingSignature,
    InvalidPublicKey(String),
    InvalidSignature(String),
    VerificationFailed,
}

impl fmt::Display for RequestSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestSigningError::MissingSignature => {
                write!(f, "Request signature is required for this operation")
            }
            RequestSigningError::InvalidPublicKey(msg) => {
                write!(f, "Invalid public key: {}", msg)
            }
            RequestSigningError::InvalidSignature(msg) => {
                write!(f, "Invalid signature format: {}", msg)
            }
            RequestSigningError::VerificationFailed => {
                write!(f, "Request signature verification failed")
            }
        }
    }
}

impl std::error::Error for RequestSigningError {}

/// Request signature metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestSignature {
    /// Base64-encoded Ed25519 signature (64 bytes)
    pub signature: String,
    /// Base64-encoded Ed25519 public key (32 bytes) - client's master_identity_key
    pub public_key: String,
    /// Timestamp when request was signed (Unix epoch seconds)
    pub timestamp: i64,
}

/// Create canonical bytes for request signing
///
/// Format: method || path || timestamp || body_hash
/// This ensures that:
/// - Method and path cannot be changed
/// - Timestamp is included (for replay protection)
/// - Body content is included via hash (prevents tampering)
///
/// # Arguments
/// * `method` - HTTP method (e.g., "POST")
/// * `path` - Request path (e.g., "/keys/upload")
/// * `timestamp` - Request timestamp (Unix epoch seconds)
/// * `body_hash` - SHA256 hash of request body (hex-encoded)
pub fn create_canonical_request_bytes(
    method: &str,
    path: &str,
    timestamp: i64,
    body_hash: &str,
) -> Vec<u8> {
    // Format: method:path:timestamp:body_hash
    let canonical_string = format!("{}:{}:{}:{}", method, path, timestamp, body_hash);
    canonical_string.into_bytes()
}

/// Compute SHA256 hash of request body
///
/// # Arguments
/// * `body` - Request body as bytes
///
/// # Returns
/// Hex-encoded SHA256 hash
pub fn compute_body_hash(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

/// Verify request signature
///
/// # Arguments
/// * `public_key_b64` - Base64-encoded Ed25519 public key (client's master_identity_key)
/// * `method` - HTTP method
/// * `path` - Request path
/// * `timestamp` - Request timestamp
/// * `body_hash` - SHA256 hash of request body
/// * `signature_b64` - Base64-encoded Ed25519 signature
///
/// # Returns
/// `Ok(())` if signature is valid, `Err` otherwise
pub fn verify_request_signature(
    public_key_b64: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    body_hash: &str,
    signature_b64: &str,
) -> Result<(), RequestSigningError> {
    // Decode public key
    let public_key_bytes = BASE64
        .decode(public_key_b64.trim())
        .map_err(|e| RequestSigningError::InvalidPublicKey(format!("Invalid base64: {}", e)))?;

    if public_key_bytes.len() != 32 {
        return Err(RequestSigningError::InvalidPublicKey(format!(
            "Public key must be 32 bytes, got {}",
            public_key_bytes.len()
        )));
    }

    let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        RequestSigningError::InvalidPublicKey("Failed to convert public key".to_string())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|e| {
        RequestSigningError::InvalidPublicKey(format!("Invalid Ed25519 public key: {}", e))
    })?;

    // Decode signature
    let signature_bytes = BASE64.decode(signature_b64.trim()).map_err(|e| {
        RequestSigningError::InvalidSignature(format!("Invalid signature base64: {}", e))
    })?;

    if signature_bytes.len() != 64 {
        return Err(RequestSigningError::InvalidSignature(format!(
            "Signature must be 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        RequestSigningError::InvalidSignature("Failed to convert signature".to_string())
    })?;

    let signature = Signature::from_bytes(&signature_array);

    // Create canonical bytes
    let canonical = create_canonical_request_bytes(method, path, timestamp, body_hash);

    // Verify signature
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| RequestSigningError::VerificationFailed)?;

    Ok(())
}

/// Extract and verify request signature from headers
///
/// Looks for signature in X-Request-Signature header (JSON format)
///
/// # Header Format
/// ```text
/// X-Request-Signature: {"signature":"...","publicKey":"...","timestamp":1234567890}
/// ```
pub fn extract_request_signature(headers: &axum::http::HeaderMap) -> Option<RequestSignature> {
    headers
        .get("x-request-signature")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str::<RequestSignature>(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_create_canonical_request_bytes() {
        let canonical =
            create_canonical_request_bytes("POST", "/keys/upload", 1234567890, "abc123");
        let expected = b"POST:/keys/upload:1234567890:abc123";
        assert_eq!(canonical, expected);
    }

    #[test]
    fn test_compute_body_hash() {
        let body = b"test body";
        let hash = compute_body_hash(body);
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_verify_request_signature() {
        // Generate key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create canonical request
        let method = "POST";
        let path = "/keys/upload";
        let timestamp = 1234567890;
        let body_hash = compute_body_hash(b"test body");
        let canonical = create_canonical_request_bytes(method, path, timestamp, &body_hash);

        // Sign request
        let signature = signing_key.sign(&canonical);

        // Verify signature
        let public_key_b64 = BASE64.encode(verifying_key.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        assert!(
            verify_request_signature(
                &public_key_b64,
                method,
                path,
                timestamp,
                &body_hash,
                &signature_b64
            )
            .is_ok()
        );
    }

    #[test]
    fn test_verify_request_signature_fails_on_tampered_request() {
        // Generate key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create canonical request
        let method = "POST";
        let path = "/keys/upload";
        let timestamp = 1234567890;
        let body_hash = compute_body_hash(b"test body");
        let canonical = create_canonical_request_bytes(method, path, timestamp, &body_hash);

        // Sign request
        let signature = signing_key.sign(&canonical);

        // Try to verify with different path (tampered)
        let public_key_b64 = BASE64.encode(verifying_key.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        assert!(
            verify_request_signature(
                &public_key_b64,
                "POST",
                "/keys/upload_tampered", // Different path
                timestamp,
                &body_hash,
                &signature_b64
            )
            .is_err()
        );
    }
}
