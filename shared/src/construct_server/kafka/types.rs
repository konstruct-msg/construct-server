use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Type of message being sent through Kafka
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum MessageType {
    /// 1-on-1 chat using Double Ratchet protocol (current implementation)
    DirectMessage,

    /// Control message (END_SESSION, etc.) - Phase 4.5
    ControlMessage,

    /// MLS group message (application message)
    #[allow(dead_code)]
    MLSMessage,

    /// MLS KeyPackage for adding user to group
    #[allow(dead_code)]
    MLSKeyPackage,

    /// MLS Welcome message for new group members
    #[allow(dead_code)]
    MLSWelcome,

    /// MLS Commit (group state change)
    #[allow(dead_code)]
    MLSCommit,

    /// MLS Proposal (proposed group change)
    #[allow(dead_code)]
    MLSProposal,

    /// Federated S2S message from another server
    #[allow(dead_code)]
    FederatedMessage,
}

/// Kafka message envelope containing all message types
///
/// This structure is serialized to JSON and stored in Kafka.
/// The partition key is derived from `recipient_id` to ensure ordering per user/group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KafkaMessageEnvelope {
    // ===== Identification =====
    /// Unique message ID (UUID v4)
    pub message_id: String,

    /// Sender ID (user UUID) or server name for S2S messages
    pub sender_id: String,

    /// Recipient ID (user UUID) or group ID
    /// Used as Kafka partition key for ordering guarantees
    pub recipient_id: String,

    /// Unix timestamp in seconds
    pub timestamp: i64,

    // ===== Message Type =====
    /// Type discriminator for routing and processing
    pub message_type: MessageType,

    // ===== Double Ratchet (DirectMessage) Fields =====
    /// Ephemeral public key for DH ratchet (32 bytes, base64-encoded)
    /// Only present for DirectMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<String>,

    /// Message number in symmetric-key ratchet chain
    /// Only present for DirectMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    // ===== MLS Fields =====
    /// MLS opaque payload (binary data, base64-encoded)
    /// Only present for MLS* types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_payload: Option<String>,

    /// MLS group ID (UUID)
    /// Only present for MLS* types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,

    // ===== Common Fields =====
    /// Base64-encoded encrypted content
    /// For DirectMessage: ChaCha20-Poly1305 sealed box
    /// For MLS: MLS-encrypted application data
    pub encrypted_payload: String,

    /// SHA-256 hash for deduplication (message_id + encrypted_payload + ephemeral_key)
    pub content_hash: String,

    /// Cryptographic suite identifier
    /// 0 = ChaCha20-Poly1305 (Double Ratchet)
    /// 1+ = MLS cipher suites (TBD)
    #[serde(default)]
    pub crypto_suite_id: u16,

    // ===== Federation Fields =====
    /// Origin server name (e.g., "server.example.com")
    /// Only present for FederatedMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_server: Option<String>,

    /// Whether this message came from S2S API (true) or local client (false)
    #[serde(default)]
    pub federated: bool,

    /// Ed25519 signature from origin server
    /// Only present for FederatedMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_signature: Option<String>,
}

impl KafkaMessageEnvelope {
    /// Create a new DirectMessage envelope (for Phase 1-2 compatibility)
    pub fn new_direct_message(
        message_id: String,
        sender_id: String,
        recipient_id: String,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        encrypted_payload: String,
        content_hash: String,
    ) -> Self {
        Self {
            message_id,
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                ephemeral_public_key,
            )),
            message_number: Some(message_number),
            mls_payload: None,
            group_id: None,
            encrypted_payload,
            content_hash,
            crypto_suite_id: 0, // ChaCha20-Poly1305
            origin_server: None,
            federated: false,
            server_signature: None,
        }
    }

    /// Validate message envelope structure
    pub fn validate(&self) -> Result<()> {
        // Check required fields
        if self.message_id.is_empty() {
            anyhow::bail!("message_id is required");
        }
        if self.sender_id.is_empty() {
            anyhow::bail!("sender_id is required");
        }
        if self.recipient_id.is_empty() {
            anyhow::bail!("recipient_id is required");
        }
        if self.encrypted_payload.is_empty() {
            anyhow::bail!("encrypted_payload is required");
        }
        if self.content_hash.is_empty() {
            anyhow::bail!("content_hash is required");
        }

        // Type-specific validation
        match self.message_type {
            MessageType::DirectMessage => {
                // Double Ratchet protocol requires these fields
                if self.ephemeral_public_key.is_none() {
                    anyhow::bail!(
                        "ephemeral_public_key required for DirectMessage (Double Ratchet)"
                    );
                }
                if self.message_number.is_none() {
                    anyhow::bail!("message_number required for DirectMessage (Double Ratchet)");
                }
            }
            MessageType::ControlMessage => {
                // Control messages (END_SESSION) have no encryption fields
                // Only basic fields (message_id, sender_id, recipient_id, timestamp) required
                // encrypted_payload is used for control message type/data
            }
            MessageType::MLSMessage
            | MessageType::MLSKeyPackage
            | MessageType::MLSWelcome
            | MessageType::MLSCommit
            | MessageType::MLSProposal => {
                if self.mls_payload.is_none() {
                    anyhow::bail!("mls_payload required for MLS messages");
                }
            }
            MessageType::FederatedMessage => {
                if self.origin_server.is_none() {
                    anyhow::bail!("origin_server required for FederatedMessage");
                }
                if self.server_signature.is_none() {
                    anyhow::bail!("server_signature required for FederatedMessage");
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Conversions from existing message types
// ============================================================================

impl From<&construct_types::ChatMessage> for KafkaMessageEnvelope {
    fn from(msg: &construct_types::ChatMessage) -> Self {
        use construct_types::MessageType as ConstructMessageType;

        match msg.message_type {
            ConstructMessageType::Regular => {
                // Calculate content hash for deduplication
                let mut hasher = Sha256::new();
                hasher.update(msg.id.as_bytes());
                hasher.update(
                    msg.ephemeral_public_key
                        .as_ref()
                        .expect("Regular message must have ephemeral_public_key"),
                );
                hasher.update(
                    msg.content
                        .as_ref()
                        .expect("Regular message must have content"),
                );
                let content_hash = format!("{:x}", hasher.finalize());

                Self {
                    message_id: msg.id.clone(),
                    sender_id: msg.from.clone(),
                    recipient_id: msg.to.clone(),
                    timestamp: msg.timestamp as i64,
                    message_type: MessageType::DirectMessage,
                    ephemeral_public_key: Some(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        msg.ephemeral_public_key.as_ref().unwrap(),
                    )),
                    message_number: msg.message_number,
                    mls_payload: None,
                    group_id: None,
                    encrypted_payload: msg.content.as_ref().unwrap().clone(),
                    content_hash,
                    crypto_suite_id: 0, // ChaCha20-Poly1305 (classic Double Ratchet)
                    origin_server: None,
                    federated: false,
                    server_signature: None,
                }
            }
            ConstructMessageType::EndSession => {
                // For control messages, hash only message_id and timestamp
                let mut hasher = Sha256::new();
                hasher.update(msg.id.as_bytes());
                hasher.update(msg.timestamp.to_string().as_bytes());
                hasher.update(b"END_SESSION");
                let content_hash = format!("{:x}", hasher.finalize());

                Self {
                    message_id: msg.id.clone(),
                    sender_id: msg.from.clone(),
                    recipient_id: msg.to.clone(),
                    timestamp: msg.timestamp as i64,
                    message_type: MessageType::ControlMessage,
                    ephemeral_public_key: None,
                    message_number: None,
                    mls_payload: None,
                    group_id: None,
                    // Use encrypted_payload to store control message type
                    encrypted_payload: "END_SESSION".to_string(),
                    content_hash,
                    crypto_suite_id: 0,
                    origin_server: None,
                    federated: false,
                    server_signature: None,
                }
            }
        }
    }
}

// For convenience, also implement From<ChatMessage> (owned)
impl From<construct_types::ChatMessage> for KafkaMessageEnvelope {
    fn from(msg: construct_types::ChatMessage) -> Self {
        Self::from(&msg)
    }
}

// ============================================================================
// Conversion from EncryptedMessage (REST API v1)
// ============================================================================

/// Context for creating KafkaMessageEnvelope from EncryptedMessage
/// Provides sender_id and message_id which are not in the message itself
pub struct EncryptedMessageContext {
    pub sender_id: String,
    pub message_id: String,
}

/// Context for creating KafkaMessageEnvelope from a proto Envelope.
///
/// E2EE contract: encrypted_payload is opaque ciphertext — server never reads it.
/// All Signal Protocol parameters live inside the payload. Server only needs
/// routing fields (sender, recipient) and the opaque blob.
pub struct ProtoEnvelopeContext {
    pub sender_id: String,
    pub recipient_id: String,
    pub message_id: String,
    pub encrypted_payload: Vec<u8>, // opaque ciphertext bytes — NOT parsed
}

impl KafkaMessageEnvelope {
    /// Create a KafkaMessageEnvelope from a proto Envelope.
    ///
    /// The server stores `encrypted_payload` verbatim (as base64) and routes the
    /// message to the recipient. It never inspects the payload contents.
    pub fn from_proto_envelope(ctx: &ProtoEnvelopeContext) -> Self {
        use base64::Engine;
        let ciphertext_b64 =
            base64::engine::general_purpose::STANDARD.encode(&ctx.encrypted_payload);

        let mut hasher = Sha256::new();
        hasher.update(ctx.message_id.as_bytes());
        hasher.update(&ctx.encrypted_payload);
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id: ctx.message_id.clone(),
            sender_id: ctx.sender_id.clone(),
            recipient_id: ctx.recipient_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: None, // inside encrypted_payload
            message_number: None,       // inside encrypted_payload
            mls_payload: None,
            group_id: None,
            encrypted_payload: ciphertext_b64,
            content_hash,
            crypto_suite_id: 0, // unknown — inside encrypted_payload
            origin_server: None,
            federated: false,
            server_signature: None,
        }
    }

    /// Create a KafkaMessageEnvelope from an EncryptedMessage with additional context
    ///
    /// The EncryptedMessage doesn't contain sender_id (it comes from JWT auth)
    /// and message_id (generated server-side), so they must be provided separately.
    pub fn from_encrypted_message(
        msg: &construct_crypto::EncryptedMessage,
        ctx: &EncryptedMessageContext,
    ) -> Self {
        // Calculate content hash for deduplication
        let mut hasher = Sha256::new();
        hasher.update(ctx.message_id.as_bytes());
        hasher.update(msg.ephemeral_public_key.as_bytes());
        hasher.update(msg.ciphertext.as_bytes());
        hasher.update(msg.message_number.to_be_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id: ctx.message_id.clone(),
            sender_id: ctx.sender_id.clone(),
            recipient_id: msg.recipient_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: Some(msg.ephemeral_public_key.clone()),
            message_number: Some(msg.message_number),
            mls_payload: None,
            group_id: None,
            encrypted_payload: msg.ciphertext.clone(),
            content_hash,
            crypto_suite_id: msg.suite_id,
            origin_server: None,
            federated: false,
            server_signature: None,
        }
    }
}

// ============================================================================
// Delivery ACK Event (Solution 1D - Privacy-Preserving)
// ============================================================================

/// Delivery ACK event for Kafka-based tracking (Phase 5+)
///
/// **SECURITY**: This event uses hashed IDs to prevent correlation attacks.
/// - Kafka logs contain ONLY hashes, not plaintext user IDs
/// - Requires SECRET_KEY + Kafka + Redis to reconstruct sender information
/// - Ephemeral Redis mappings (TTL 7 days) enable ACK routing
///
/// Flow:
/// 1. Message queued → Producer writes DeliveryAckEvent to Kafka
///    - All IDs are HMAC-SHA256 hashed
///    - Redis stores temporary mapping: message_hash → {sender_id, recipient_id}
/// 2. Recipient acknowledges → Consumer reads Kafka event
///    - Looks up sender_id in Redis using message_hash
///    - Sends "delivered" ACK via WebSocket
///    - Deletes Redis mapping (one-time use)
///
/// Privacy properties:
/// - ✅ Kafka logs reveal nothing about who sent what to whom
/// - ✅ Requires both Kafka access AND Redis access AND SECRET_KEY to correlate
/// - ✅ Ephemeral Redis data auto-expires (7 days TTL)
/// - ✅ Batching prevents timing correlation (5-second buffer)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryAckEvent {
    /// HMAC-SHA256 hash of message_id
    /// Used as key in Redis for ephemeral lookup
    pub message_hash: String,

    /// HMAC-SHA256 hash of sender_id
    /// NEVER store plaintext sender_id in Kafka
    /// This prevents correlation attacks on Kafka logs
    pub sender_id_hash: String,

    /// HMAC-SHA256 hash of recipient_id
    /// NEVER store plaintext recipient_id in Kafka
    /// This prevents correlation attacks on Kafka logs
    pub recipient_id_hash: String,

    /// Unix timestamp when message was delivered (seconds)
    pub delivered_at: i64,

    /// Original message_id (for deduplication by consumer)
    /// NOTE: This is the ONLY unhashed field, used to prevent duplicate ACKs
    /// Consumer uses this to check if ACK was already processed
    pub message_id: String,
}

impl DeliveryAckEvent {
    /// Create a new DeliveryAckEvent with hashed IDs
    ///
    /// # Arguments
    /// * `message_id` - Original message ID (UUID)
    /// * `message_hash` - HMAC-SHA256(message_id, SECRET_KEY)
    /// * `sender_id_hash` - HMAC-SHA256(sender_id, SECRET_KEY)
    /// * `recipient_id_hash` - HMAC-SHA256(recipient_id, SECRET_KEY)
    pub fn new(
        message_id: String,
        message_hash: String,
        sender_id_hash: String,
        recipient_id_hash: String,
    ) -> Self {
        Self {
            message_hash,
            sender_id_hash,
            recipient_id_hash,
            delivered_at: chrono::Utc::now().timestamp(),
            message_id,
        }
    }

    /// Validate the event structure
    pub fn validate(&self) -> Result<()> {
        if self.message_hash.is_empty() {
            anyhow::bail!("message_hash is required");
        }
        if self.message_hash.len() != 64 {
            anyhow::bail!("message_hash must be 64 hex characters (SHA256)");
        }
        if self.sender_id_hash.is_empty() {
            anyhow::bail!("sender_id_hash is required");
        }
        if self.sender_id_hash.len() != 64 {
            anyhow::bail!("sender_id_hash must be 64 hex characters (SHA256)");
        }
        if self.recipient_id_hash.is_empty() {
            anyhow::bail!("recipient_id_hash is required");
        }
        if self.recipient_id_hash.len() != 64 {
            anyhow::bail!("recipient_id_hash must be 64 hex characters (SHA256)");
        }
        if self.message_id.is_empty() {
            anyhow::bail!("message_id is required");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_message_envelope_creation() {
        let envelope = KafkaMessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "user-456".to_string(),
            "user-789".to_string(),
            vec![0u8; 32], // 32-byte ephemeral key
            42,            // message number
            "encrypted".to_string(),
            "hash123".to_string(),
        );

        assert_eq!(envelope.message_type, MessageType::DirectMessage);
        assert!(envelope.ephemeral_public_key.is_some());
        assert_eq!(envelope.message_number, Some(42));
        assert!(!envelope.federated);
    }

    #[test]
    fn test_from_proto_envelope_e2ee_opaque() {
        // Verify that from_proto_envelope stores encrypted_payload as opaque base64
        // without deserializing it — server never reads crypto params from the payload.
        let fake_ciphertext = b"this_is_not_json_it_is_opaque_bytes";
        let ctx = ProtoEnvelopeContext {
            sender_id: "sender-uuid".to_string(),
            recipient_id: "recipient-uuid".to_string(),
            message_id: "msg-uuid".to_string(),
            encrypted_payload: fake_ciphertext.to_vec(),
        };

        let envelope = KafkaMessageEnvelope::from_proto_envelope(&ctx);

        assert_eq!(envelope.sender_id, "sender-uuid");
        assert_eq!(envelope.recipient_id, "recipient-uuid");
        // Crypto params must NOT be exposed outside the payload
        assert!(
            envelope.ephemeral_public_key.is_none(),
            "ephemeral_public_key must not be visible to server"
        );
        assert!(
            envelope.message_number.is_none(),
            "message_number must not be visible to server"
        );
        assert_eq!(
            envelope.crypto_suite_id, 0,
            "crypto_suite_id must not be known to server"
        );

        // The payload must be the base64 of the raw ciphertext bytes
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&envelope.encrypted_payload)
            .expect("KafkaMessageEnvelope.encrypted_payload must be valid base64");
        assert_eq!(
            decoded, fake_ciphertext,
            "encrypted_payload must be stored verbatim (base64), not parsed"
        );
    }
}
