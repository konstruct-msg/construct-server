use serde::{Deserialize, Serialize};

/// Nested key bundle structure for public key response
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6A
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyBundleResponse {
    /// Base64-encoded JSON bundle data (contains cipher suites, keys)
    pub bundle_data: String,
    /// Base64-encoded X25519 identity key (for key exchange/sessions)
    pub master_identity_key: String,
    /// Base64-encoded Ed25519 signature of bundle_data (64 bytes)
    pub signature: String,
}

/// Public key response structure matching the spec
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6A
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    /// Nested key bundle with bundleData and masterIdentityKey
    pub key_bundle: KeyBundleResponse,
    /// Username of the user
    pub username: String,
    /// Base64-encoded Ed25519 verifying key (REQUIRED for invite verification)
    pub verifying_key: String,
}

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

/// Request body for PATCH /api/v1/users/me/public-key
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6B
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVerifyingKeyRequest {
    /// Base64-encoded Ed25519 verifying key
    pub verifying_key: String,
    /// Optional reason for update (e.g., "invite_signature_mismatch")
    pub reason: Option<String>,
}

/// Request body for POST /api/v1/messages/confirm
#[derive(Debug, Deserialize)]
pub struct ConfirmMessageRequest {
    /// Temporary ID from Phase 1 (send_message response)
    #[serde(rename = "tempId")]
    pub temp_id: String,
}
