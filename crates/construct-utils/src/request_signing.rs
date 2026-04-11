// Re-exported from shared/routes/request_signing.rs — canonical home for signing utils

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_types::api::RequestSignature;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
            RequestSigningError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
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

pub fn create_canonical_request_bytes(
    method: &str,
    path: &str,
    timestamp: i64,
    body_hash: &str,
) -> Vec<u8> {
    let canonical_string = format!("{}:{}:{}:{}", method, path, timestamp, body_hash);
    canonical_string.into_bytes()
}

pub fn compute_body_hash(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

pub fn verify_request_signature(
    public_key_b64: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    body_hash: &str,
    signature_b64: &str,
) -> Result<(), RequestSigningError> {
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
    let canonical = create_canonical_request_bytes(method, path, timestamp, body_hash);

    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| RequestSigningError::VerificationFailed)?;

    Ok(())
}

pub fn extract_request_signature(headers: &axum::http::HeaderMap) -> Option<RequestSignature> {
    headers
        .get("x-request-signature")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str::<RequestSignature>(s).ok())
}
