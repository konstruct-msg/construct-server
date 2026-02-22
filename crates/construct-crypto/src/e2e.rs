use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Encrypted message as stored on the server
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEncryptedMessage {
    /// Base64 encoded [ephemeral_public (32 bytes) || ciphertext]
    pub content: String,

    /// Base64 encoded nonce (12 bytes)
    pub nonce: String,

    /// Base64 encoded sender's identity public key (32 bytes)
    pub sender_identity: String,

    /// Recipient user ID
    pub recipient_id: String,

    /// Sender user ID
    pub sender_id: String,

    /// Message timestamp (server time)
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Message type for routing
    pub message_type: MessageType,
}

/// Message type for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    /// Regular text message
    TextMessage,
    /// Prekey bundle for key updates
    PrekeyBundle,
    /// Encrypted media file
    MediaMessage,
    /// System notification
    SystemMessage,
}

/// Server-side validation utilities
pub struct ServerCryptoValidator;

#[allow(dead_code)]
impl ServerCryptoValidator {
    /// Validates the format of an encrypted message
    ///
    /// Note: Server CANNOT validate cryptographic correctness,
    /// only basic format and length constraints.
    pub fn validate_encrypted_message(msg: &StoredEncryptedMessage) -> Result<()> {
        // 1. Декодируем base64
        let content_bytes = general_purpose::STANDARD
            .decode(&msg.content)
            .context("Invalid base64 in content")?;

        let nonce_bytes = general_purpose::STANDARD
            .decode(&msg.nonce)
            .context("Invalid base64 in nonce")?;

        let sender_bytes = general_purpose::STANDARD
            .decode(&msg.sender_identity)
            .context("Invalid base64 in sender_identity")?;

        // 2. Проверяем длины
        if content_bytes.len() < 32 + 16 {
            // min: ephemeral_public + minimal ciphertext
            return Err(anyhow::anyhow!("Content too short"));
        }

        if nonce_bytes.len() != 12 {
            return Err(anyhow::anyhow!("Nonce must be 12 bytes"));
        }

        if sender_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Sender identity must be 32 bytes"));
        }

        // 3. Проверяем, что ephemeral_public имеет корректную длину
        // (первые 32 байта content должны быть публичным ключом)
        // Сервер не может проверить, что это валидная точка на кривой!

        // 4. Проверяем идентификаторы пользователей
        if msg.recipient_id.is_empty() || msg.sender_id.is_empty() {
            return Err(anyhow::anyhow!("User IDs cannot be empty"));
        }

        // 5. Проверяем, что отправитель не отправляет сообщение сам себе
        // (это могло бы быть признаком атаки)
        if msg.recipient_id == msg.sender_id {
            return Err(anyhow::anyhow!("Cannot send message to self"));
        }

        Ok(())
    }

    /// Validates BundleData for API v3 (crypto-agility)
    ///
    /// Server validates format and key lengths based on suite_id,
    /// but DOES NOT verify the cryptographic signature.
    /// Signature verification is the responsibility of clients.
    ///
    /// # Arguments
    /// * `bundle_data` - The bundle data to validate
    /// * `allow_empty_user_id` - If true, allows empty user_id (used during registration)
    pub fn validate_bundle_data(bundle_data: &BundleData, allow_empty_user_id: bool) -> Result<()> {
        // 1. Check that we have at least one suite
        if bundle_data.supported_suites.is_empty() {
            return Err(anyhow::anyhow!(
                "Bundle must contain at least one cipher suite"
            ));
        }

        // 2. Check user_id is not empty (unless explicitly allowed during registration)
        if !allow_empty_user_id && bundle_data.user_id.is_empty() {
            return Err(anyhow::anyhow!("User ID cannot be empty"));
        }

        // 3. Validate timestamp format (ISO8601)
        if chrono::DateTime::parse_from_rfc3339(&bundle_data.timestamp).is_err() {
            return Err(anyhow::anyhow!(
                "Invalid timestamp format (expected ISO8601)"
            ));
        }

        // 4. Validate each suite's key material
        for suite in &bundle_data.supported_suites {
            Self::validate_suite_key_material(suite)
                .with_context(|| format!("Invalid key material for suite_id {}", suite.suite_id))?;
        }

        Ok(())
    }

    /// Validates key material for a specific cipher suite
    fn validate_suite_key_material(suite: &SuiteKeyMaterial) -> Result<()> {
        match suite.suite_id {
            suite_ids::CLASSIC_X25519 => {
                // X25519 keys are 32 bytes, Ed25519 keys are 32 bytes
                let identity_bytes = general_purpose::STANDARD
                    .decode(&suite.identity_key)
                    .context("Invalid base64 in identity_key")?;

                let prekey_bytes = general_purpose::STANDARD
                    .decode(&suite.signed_prekey)
                    .context("Invalid base64 in signed_prekey")?;

                // Validate signed_prekey_signature (required)
                let signature_bytes = general_purpose::STANDARD
                    .decode(&suite.signed_prekey_signature)
                    .context("Invalid base64 in signed_prekey_signature")?;

                if signature_bytes.len() != 64 {
                    return Err(anyhow::anyhow!(
                        "signed_prekey_signature must be 64 bytes (Ed25519 signature) for suite {}",
                        suite.suite_id
                    ));
                }

                if identity_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Identity key must be 32 bytes for suite {}",
                        suite.suite_id
                    ));
                }

                if prekey_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Signed prekey must be 32 bytes for suite {}",
                        suite.suite_id
                    ));
                }

                // Validate one-time prekeys if present
                for (idx, otpk) in suite.one_time_prekeys.iter().enumerate() {
                    let otpk_bytes = general_purpose::STANDARD
                        .decode(otpk)
                        .with_context(|| format!("Invalid base64 in one_time_prekey[{}]", idx))?;

                    if otpk_bytes.len() != 32 {
                        return Err(anyhow::anyhow!(
                            "One-time prekey[{}] must be 32 bytes for suite {}",
                            idx,
                            suite.suite_id
                        ));
                    }
                }

                Ok(())
            }
            suite_ids::PQ_HYBRID_KYBER => {
                // Post-Quantum Hybrid: X25519+ML-KEM-768 + Ed25519+ML-DSA-65
                #[cfg(feature = "post-quantum")]
                {
                    use crate::pqc::validation;
                    validation::validate_hybrid_suite_key_material(suite)
                }
                #[cfg(not(feature = "post-quantum"))]
                {
                    Err(anyhow::anyhow!(
                        "Post-quantum hybrid suite (suite_id={}) is not enabled. \
                         Enable with feature flag: cargo build --features post-quantum",
                        suite.suite_id
                    ))
                }
            }
            _ => Err(anyhow::anyhow!(
                "Unsupported suite_id: {}. Supported: {} (CLASSIC_X25519), {} (PQ_HYBRID_KYBER)",
                suite.suite_id,
                suite_ids::CLASSIC_X25519,
                suite_ids::PQ_HYBRID_KYBER
            )),
        }
    }

    /// Validates UploadableKeyBundle for API v3
    ///
    /// Now includes cryptographic signature verification using Ed25519.
    /// The server verifies that the bundle_data was signed by the master_identity_key.
    ///
    /// # Arguments
    /// * `bundle` - The uploadable key bundle to validate
    /// * `allow_empty_user_id` - If true, allows empty user_id (used during registration)
    pub fn validate_uploadable_key_bundle(
        bundle: &UploadableKeyBundle,
        allow_empty_user_id: bool,
    ) -> Result<()> {
        // 1. Decode bundle_data first to determine suite type
        let bundle_data_bytes = general_purpose::STANDARD
            .decode(&bundle.bundle_data)
            .context("Invalid base64 in bundle_data")?;

        let bundle_data: BundleData =
            serde_json::from_slice(&bundle_data_bytes).context("Invalid JSON in bundle_data")?;

        // 2. Validate master_identity_key format based on suite
        // Check if any suite uses hybrid (suite_id=2) - if so, use hybrid signature format
        let has_hybrid_suite = bundle_data
            .supported_suites
            .iter()
            .any(|s| s.suite_id == suite_ids::PQ_HYBRID_KYBER);
        let is_classical_only = bundle_data
            .supported_suites
            .iter()
            .all(|s| s.suite_id == suite_ids::CLASSIC_X25519);

        let master_key_bytes = general_purpose::STANDARD
            .decode(&bundle.master_identity_key)
            .context("Invalid base64 in master_identity_key")?;

        // 3. Validate signature format based on suite type
        let signature_bytes = general_purpose::STANDARD
            .decode(&bundle.signature)
            .context("Invalid base64 in signature")?;

        if has_hybrid_suite {
            // Hybrid suite: validate hybrid signature and master key formats
            #[cfg(feature = "post-quantum")]
            {
                use crate::pqc::validation;
                validation::validate_hybrid_master_identity_key(&master_key_bytes)
                    .context("Invalid hybrid master identity key format")?;

                validation::validate_hybrid_signature(&signature_bytes)
                    .context("Invalid hybrid signature format")?;

                // Note: Hybrid signature verification requires both Ed25519 and ML-DSA-65
                // This will be implemented in the hybrid module when feature is enabled
                // For now, we only validate format
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                return Err(anyhow::anyhow!(
                    "Post-quantum hybrid suite detected but feature is not enabled. \
                     Enable with: cargo build --features post-quantum"
                ));
            }
        } else if is_classical_only {
            // Classical suite: validate Ed25519 format
            if master_key_bytes.len() != 32 {
                return Err(anyhow::anyhow!(
                    "Master identity key must be 32 bytes for classical suite (Ed25519)"
                ));
            }

            if signature_bytes.len() != 64 {
                return Err(anyhow::anyhow!(
                    "Signature must be 64 bytes for classical suite (Ed25519)"
                ));
            }
        } else {
            // Mixed suites (both classical and hybrid) - use hybrid format for signature
            #[cfg(feature = "post-quantum")]
            {
                use crate::pqc::validation;
                validation::validate_hybrid_master_identity_key(&master_key_bytes)
                    .context("Invalid hybrid master identity key format (mixed suites)")?;

                validation::validate_hybrid_signature(&signature_bytes)
                    .context("Invalid hybrid signature format (mixed suites)")?;
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                return Err(anyhow::anyhow!(
                    "Mixed suites (classical + hybrid) require post-quantum feature. \
                     Enable with: cargo build --features post-quantum"
                ));
            }
        }

        // 4. Validate the bundle_data content (format, lengths, etc.)
        // Note: bundle_data was already decoded above for suite detection
        Self::validate_bundle_data(&bundle_data, allow_empty_user_id)?;

        // 5. SECURITY: Verify signature (Ed25519 for classical, hybrid for PQ)
        if has_hybrid_suite || !is_classical_only {
            // Hybrid signature verification
            #[cfg(feature = "post-quantum")]
            {
                // Extract Ed25519 part from hybrid signature (first 64 bytes) for backward compatibility
                // Full hybrid verification will be implemented when hybrid module is complete
                let ed25519_sig_bytes: [u8; 64] =
                    signature_bytes[0..64].try_into().map_err(|_| {
                        anyhow::anyhow!("Failed to extract Ed25519 signature from hybrid signature")
                    })?;

                // Extract Ed25519 part from hybrid master key (first 32 bytes)
                let ed25519_key_bytes: [u8; 32] =
                    master_key_bytes[0..32].try_into().map_err(|_| {
                        anyhow::anyhow!("Failed to extract Ed25519 key from hybrid master key")
                    })?;

                let verifying_key = VerifyingKey::from_bytes(&ed25519_key_bytes)
                    .context("Invalid Ed25519 master_identity_key format in hybrid key")?;

                let signature = Signature::from_bytes(&ed25519_sig_bytes);

                // Verify Ed25519 signature (classical part of hybrid)
                verifying_key
                    .verify(&bundle_data_bytes, &signature)
                    .context("Ed25519 signature verification failed in hybrid signature - bundle may be tampered")?;

                // TODO: Verify ML-DSA-65 signature (PQ part) when hybrid module is complete
                // This requires parsing the full hybrid signature and master key
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                // Should not reach here due to validation above, but just in case
                return Err(anyhow::anyhow!(
                    "Post-quantum hybrid signature verification requires post-quantum feature"
                ));
            }
        } else {
            // Classical Ed25519 signature verification
            let master_key_array: [u8; 32] = master_key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert master_identity_key to array"))?;

            let verifying_key = VerifyingKey::from_bytes(&master_key_array)
                .context("Invalid Ed25519 master_identity_key format")?;

            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert signature to array"))?;

            let signature = Signature::from_bytes(&signature_array);

            // CRITICAL: Verify signature over the exact bytes that were signed
            verifying_key
                .verify(&bundle_data_bytes, &signature)
                .context("Ed25519 signature verification failed - bundle may be tampered or signed with different key")?;
        }

        Ok(())
    }

    /// Validates EncryptedMessage for API v3 (Double Ratchet Protocol)
    ///
    /// Validates:
    /// 1. recipient_id is not empty
    /// 2. suite_id is supported
    /// 3. ephemeral_public_key has correct length for suite
    /// 4. ciphertext has minimum length (nonce + tag)
    pub fn validate_encrypted_message_v3(msg: &EncryptedMessage) -> Result<()> {
        // 1. Check recipient_id is not empty
        if msg.recipient_id.is_empty() {
            return Err(anyhow::anyhow!("Recipient ID cannot be empty"));
        }

        // 2. Check ephemeral_public_key is not empty
        if msg.ephemeral_public_key.is_empty() {
            return Err(anyhow::anyhow!(
                "ephemeral_public_key is required for Double Ratchet"
            ));
        }

        // 3. Decode and validate ephemeral_public_key
        let ephemeral_bytes = general_purpose::STANDARD
            .decode(&msg.ephemeral_public_key)
            .context("Invalid base64 in ephemeral_public_key")?;

        // 4. Suite-specific validation
        match msg.suite_id {
            suite_ids::CLASSIC_X25519 => {
                // X25519 ephemeral key: 32 bytes
                if ephemeral_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "ephemeral_public_key must be 32 bytes for suite {} (got {} bytes)",
                        msg.suite_id,
                        ephemeral_bytes.len()
                    ));
                }

                // Ciphertext: nonce (12 bytes) + encrypted + tag (16 bytes)
                // Minimum: 12 + 0 + 16 = 28 bytes
                let ciphertext_bytes = general_purpose::STANDARD
                    .decode(&msg.ciphertext)
                    .context("Invalid base64 in ciphertext")?;

                if ciphertext_bytes.len() < 28 {
                    return Err(anyhow::anyhow!(
                        "Ciphertext too short for suite {} (expected at least 28 bytes, got {})",
                        msg.suite_id,
                        ciphertext_bytes.len()
                    ));
                }

                Ok(())
            }
            suite_ids::PQ_HYBRID_KYBER => {
                // Hybrid ephemeral key: 32 (X25519) + 1184 (ML-KEM-768) = 1216 bytes
                #[cfg(feature = "post-quantum")]
                {
                    use crate::pqc::validation;

                    if ephemeral_bytes.len() != 1216 {
                        return Err(anyhow::anyhow!(
                            "ephemeral_public_key must be 1216 bytes for hybrid suite {} (got {} bytes)",
                            msg.suite_id,
                            ephemeral_bytes.len()
                        ));
                    }

                    let ciphertext_bytes = general_purpose::STANDARD
                        .decode(&msg.ciphertext)
                        .context("Invalid base64 in ciphertext")?;

                    validation::validate_hybrid_ciphertext(&ciphertext_bytes)
                }
                #[cfg(not(feature = "post-quantum"))]
                {
                    Err(anyhow::anyhow!(
                        "Post-quantum hybrid suite (suite_id={}) is not enabled. \
                         Enable with feature flag: cargo build --features post-quantum",
                        msg.suite_id
                    ))
                }
            }
            _ => Err(anyhow::anyhow!(
                "Unsupported suite_id: {}. Supported: {} (CLASSIC_X25519), {} (PQ_HYBRID_KYBER)",
                msg.suite_id,
                suite_ids::CLASSIC_X25519,
                suite_ids::PQ_HYBRID_KYBER
            )),
        }
    }
}

/// Decodes a base64 string to bytes
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

// ============================================================================
// API v3 Structures for Crypto-Agility
// ============================================================================

/// Suite ID identifies a set of cryptographic primitives (KEM, Signature, AEAD, Hash)
pub type SuiteId = u16;

/// Known Suite IDs
pub mod suite_ids {
    use super::SuiteId;

    /// X25519 + Ed25519 + ChaCha20-Poly1305 + HKDF-SHA256 (baseline classic suite)
    pub const CLASSIC_X25519: SuiteId = 1;

    /// Post-Quantum Hybrid: X25519+ML-KEM-768 + Ed25519+ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA256
    /// Security: 128-bit classical + 192-bit post-quantum (hybrid approach)
    /// Format: Both classical and PQ components are present and validated
    #[cfg(feature = "post-quantum")]
    pub const PQ_HYBRID_KYBER: SuiteId = 2;

    /// Suite ID 2 (placeholder when post-quantum feature is disabled)
    /// When enabled, this becomes PQ_HYBRID_KYBER
    #[cfg(not(feature = "post-quantum"))]
    pub const PQ_HYBRID_KYBER: SuiteId = 2;

    /// Check if a suite ID is supported
    pub fn is_supported(suite_id: SuiteId) -> bool {
        matches!(suite_id, CLASSIC_X25519 | PQ_HYBRID_KYBER)
    }

    /// Get suite name for logging/debugging
    pub fn suite_name(suite_id: SuiteId) -> &'static str {
        match suite_id {
            CLASSIC_X25519 => "CLASSIC_X25519",
            PQ_HYBRID_KYBER => "PQ_HYBRID_KYBER",
            _ => "UNKNOWN",
        }
    }
}

/// Key material for a single cipher suite
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuiteKeyMaterial {
    /// Cipher suite identifier
    pub suite_id: SuiteId,

    /// Base64-encoded identity key (length depends on suite_id)
    pub identity_key: String,

    /// Base64-encoded signed prekey (length depends on suite_id)
    pub signed_prekey: String,

    /// Base64-encoded Ed25519 signature for signed_prekey (64 bytes)
    /// This signature is created with prologue (X3DH protocol + suite_id) for security
    pub signed_prekey_signature: String,

    /// Optional Base64-encoded one-time prekeys
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_time_prekeys: Vec<String>,
}

/// Bundle data that gets serialized and signed
/// This is the canonical format that the master identity key signs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleData {
    /// User ID this bundle belongs to
    pub user_id: String,

    /// Timestamp when bundle was created (ISO8601)
    pub timestamp: String,

    /// List of supported cipher suites with their key material
    pub supported_suites: Vec<SuiteKeyMaterial>,
}

impl BundleData {
    /// Returns the canonical byte representation for signing/verification
    ///
    /// Uses JSON serialization with deterministic field ordering (via serde_json)
    /// This matches what the client signed when creating the bundle
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // Use serde_json::to_vec which produces canonical JSON (deterministic ordering)
        // This is the same format that the client signed
        serde_json::to_vec(self).context("Failed to serialize BundleData to canonical bytes")
    }
}

/// Uploadable key bundle that the client sends to the server
/// Contains the bundle data and its cryptographic signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadableKeyBundle {
    /// Base64-encoded master identity key (Ed25519, 32 bytes)
    /// This key is used to verify the signature
    pub master_identity_key: String,

    /// Base64-encoded serialized BundleData
    pub bundle_data: String,

    /// Base64-encoded Ed25519 signature of bundle_data (64 bytes)
    pub signature: String,

    /// Optional: Nonce for replay protection (base64-encoded random bytes, 16-32 bytes)
    /// Required for critical operations to prevent replay attacks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Optional: Timestamp for replay protection (Unix epoch seconds)
    /// Server validates that timestamp is within 5 minutes of current time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

/// Encrypted message for API v3 (Double Ratchet Protocol)
///
/// This structure follows the Construct Protocol specification.
/// See docs/PROTOCOL_SPECIFICATION.md for details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedMessage {
    /// Recipient user ID (UUID)
    pub recipient_id: String,

    /// Cipher suite identifier (1 = CLASSIC_X25519, 2 = PQ_HYBRID_KYBER)
    pub suite_id: SuiteId,

    // ===== Double Ratchet Fields =====
    /// Base64-encoded sender's current DH ratchet public key
    /// For suite 1: 32 bytes (X25519)
    /// For suite 2: 1216 bytes (X25519 + ML-KEM-768)
    pub ephemeral_public_key: String,

    /// Message number in current sending chain (starts at 0)
    pub message_number: u32,

    /// Number of messages in previous sending chain
    /// Used for out-of-order message handling
    #[serde(default)]
    pub previous_chain_length: u32,

    // ===== Encrypted Content =====
    /// Base64-encoded AEAD ciphertext
    /// Format: nonce (12 bytes) || encrypted_plaintext || tag (16 bytes)
    pub ciphertext: String,

    // ===== Replay Protection =====
    /// Optional: Client-generated nonce for additional replay protection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Optional: Client timestamp (Unix epoch seconds)
    /// Server rejects messages older than 5 minutes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,

    // ===== 2-Phase Commit Protocol (Week R2) =====
    /// Optional: Temporary ID for idempotent message delivery
    /// Client generates UUID and includes it for retry safety
    /// If network fails after server writes to Kafka, client can retry with same temp_id
    /// Server will detect duplicate and return existing message_id (idempotent)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_id: Option<String>,
}
