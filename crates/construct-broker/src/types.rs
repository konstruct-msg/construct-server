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

    /// Sealed sender message — sender identity is hidden from server.
    /// `sender_id` is empty; recipient extracted from SealedInner.recipient_user_id.
    SealedSender,

    /// Delivery receipt relayed from recipient back to original sender.
    /// `sender_id` = original message sender (receives the receipt).
    /// `recipient_id` = receipt sender (who acknowledged the message).
    /// `encrypted_payload` = JSON-serialized receipt info.
    Receipt,

    /// Sender sync copy delivered to the sender's own other devices.
    /// Same encrypted payload structure as DirectMessage but sent to a device
    /// belonging to the sender (same user_id, different device_id).
    /// Client displays it as a sent bubble, not an incoming message.
    SenderSync,
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

    // ===== Sealed Sender Fields =====
    /// True when this is a sealed-sender message. `sender_id` will be empty.
    #[serde(default)]
    pub is_sealed_sender: bool,

    /// Base64-encoded serialized `SealedInner` protobuf — opaque to server.
    /// Contains recipient_user_id (plaintext for routing) + E2EE payload (opaque).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_inner_b64: Option<String>,

    // ===== Edit Fields =====
    /// Original message ID that this envelope replaces (edit flow).
    /// When set, the recipient client replaces the original message in their local store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edits_message_id: Option<String>,
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
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
        }
    }

    /// Create a KafkaMessageEnvelope for a sealed-sender message.
    ///
    /// The server does NOT know the sender. `recipient_id` is extracted from the
    /// plaintext `SealedInner.recipient_user_id` field before calling this.
    /// The full `sealed_inner` bytes are stored opaquely for delivery to the client.
    pub fn from_sealed_sender(
        message_id: String,
        recipient_id: String,
        sealed_inner: Vec<u8>,
    ) -> Self {
        use base64::Engine;
        let sealed_b64 = base64::engine::general_purpose::STANDARD.encode(&sealed_inner);

        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(&sealed_inner);
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id,
            sender_id: String::new(), // intentionally empty — sealed sender
            recipient_id,
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::SealedSender,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: sealed_b64.clone(),
            content_hash,
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: true,
            sealed_inner_b64: Some(sealed_b64),
            edits_message_id: None,
        }
    }

    /// Create a SESSION_RESET control envelope.
    ///
    /// Used by the server to signal that the receiving party should discard their
    /// current session state and re-initialise (fetch a fresh prekey bundle).
    ///
    /// `trigger_user_id` — the user whose decryption failed (triggers the reset).
    /// `recipient_id` — who receives this SESSION_RESET signal (original sender).
    pub fn new_session_reset(trigger_user_id: String, recipient_id: String) -> Self {
        let message_id = uuid::Uuid::new_v4().to_string();
        let payload = "SESSION_RESET";

        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(payload.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id,
            sender_id: trigger_user_id,
            recipient_id,
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::ControlMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: payload.to_string(),
            content_hash,
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
        }
    }

    /// Create a KEY_SYNC control envelope.
    /// Recipient will perform a full X3DH re-init with `sender_user_id`.
    pub fn new_key_sync(sender_user_id: String, recipient_id: String) -> Self {
        let message_id = uuid::Uuid::new_v4().to_string();
        let payload = "KEY_SYNC";

        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(payload.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id,
            sender_id: sender_user_id,
            recipient_id,
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::ControlMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: payload.to_string(),
            content_hash,
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
        }
    }

    /// Validate message envelope structure
    pub fn validate(&self) -> Result<()> {
        // Check required fields
        if self.message_id.is_empty() {
            anyhow::bail!("message_id is required");
        }
        // sender_id is intentionally empty for sealed sender messages
        if !self.is_sealed_sender && self.sender_id.is_empty() {
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
                // Note: ephemeral_public_key and message_number are optional here.
                // For E2EE opaque payloads (gRPC path), these fields live inside
                // encrypted_payload and are NOT visible to the server.
                // Only the REST/ChatMessage path populates them externally.
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
            MessageType::SealedSender => {
                if self.sealed_inner_b64.is_none() {
                    anyhow::bail!("sealed_inner_b64 required for SealedSender");
                }
            }
            MessageType::Receipt => {
                // encrypted_payload contains receipt JSON — already checked above
            }
            MessageType::SenderSync => {
                // Treated identically to DirectMessage — opaque ciphertext bytes.
            }
        }

        Ok(())
    }

    /// Create a KafkaMessageEnvelope representing a delivery receipt.
    ///
    /// `original_sender_id` — who originally sent the message (receives this receipt).
    /// `receipt_sender_id` — who is sending the receipt (the message recipient).
    /// `message_ids` — the messages being acknowledged.
    /// `status` — receipt status string (e.g. "delivered", "read").
    pub fn from_receipt(
        original_sender_id: String,
        receipt_sender_id: String,
        message_ids: Vec<String>,
        status: &str,
    ) -> Self {
        let receipt_id = uuid::Uuid::new_v4().to_string();
        let payload = serde_json::json!({
            "message_ids": message_ids,
            "status": status,
            "timestamp": chrono::Utc::now().timestamp_millis(),
        })
        .to_string();

        let mut hasher = Sha256::new();
        hasher.update(receipt_id.as_bytes());
        hasher.update(payload.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id: receipt_id,
            sender_id: original_sender_id,   // receives the receipt
            recipient_id: receipt_sender_id, // sent the receipt
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::Receipt,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: payload,
            content_hash,
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
        }
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
                    is_sealed_sender: false,
                    sealed_inner_b64: None,
                    edits_message_id: None,
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
                    is_sealed_sender: false,
                    sealed_inner_b64: None,
                    edits_message_id: None,
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
    /// Proto ContentType value (from Envelope.content_type).
    /// Used to classify control messages (SESSION_RESET=21, KEY_SYNC=22).
    pub content_type: i32,
}

impl KafkaMessageEnvelope {
    /// Create a KafkaMessageEnvelope from a proto Envelope.
    ///
    /// The server stores `encrypted_payload` verbatim (as base64) and routes the
    /// message to the recipient. It never inspects the payload contents.
    pub fn from_proto_envelope(ctx: &ProtoEnvelopeContext) -> Self {
        use base64::Engine;

        // Map proto ContentType to Kafka MessageType + payload representation.
        // SESSION_RESET=21 and KEY_SYNC=22 are control messages — store their type
        // as the payload string so convert_kafka_envelope_to_proto can recover it.
        const CONTENT_TYPE_SESSION_RESET: i32 = 21;
        const CONTENT_TYPE_KEY_SYNC: i32 = 22;

        let (message_type, encoded_payload) = match ctx.content_type {
            CONTENT_TYPE_SESSION_RESET => {
                (MessageType::ControlMessage, "SESSION_RESET".to_string())
            }
            CONTENT_TYPE_KEY_SYNC => (MessageType::ControlMessage, "KEY_SYNC".to_string()),
            _ => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&ctx.encrypted_payload);
                (MessageType::DirectMessage, b64)
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(ctx.message_id.as_bytes());
        hasher.update(&ctx.encrypted_payload);
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id: ctx.message_id.clone(),
            sender_id: ctx.sender_id.clone(),
            recipient_id: ctx.recipient_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            message_type,
            ephemeral_public_key: None, // inside encrypted_payload
            message_number: None,       // inside encrypted_payload
            mls_payload: None,
            group_id: None,
            encrypted_payload: encoded_payload,
            content_hash,
            crypto_suite_id: 0, // unknown — inside encrypted_payload
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
        }
    }

    /// Create a KafkaMessageEnvelope for an edit operation.
    ///
    /// Delivers a new encrypted payload to the recipient that replaces
    /// the original message identified by `original_message_id`.
    /// The server tracks edit count via Redis externally (`edits:{original_message_id}`).
    pub fn from_edit(
        new_message_id: String,
        sender_id: String,
        recipient_id: String,
        original_message_id: String,
        new_encrypted_payload: Vec<u8>,
    ) -> Self {
        use base64::Engine;
        let ciphertext_b64 =
            base64::engine::general_purpose::STANDARD.encode(&new_encrypted_payload);

        let mut hasher = Sha256::new();
        hasher.update(new_message_id.as_bytes());
        hasher.update(&new_encrypted_payload);
        hasher.update(original_message_id.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        Self {
            message_id: new_message_id,
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: ciphertext_b64,
            content_hash,
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: Some(original_message_id),
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
            content_type: 0,
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

    // ── from_edit ─────────────────────────────────────────────────────────────

    #[test]
    fn test_from_edit_sets_edits_message_id() {
        let env = KafkaMessageEnvelope::from_edit(
            "new-msg-id".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            "original-msg-id".to_string(),
            b"new encrypted content".to_vec(),
        );

        assert_eq!(
            env.edits_message_id,
            Some("original-msg-id".to_string()),
            "from_edit must set edits_message_id to the original message id"
        );
        assert_eq!(env.message_id, "new-msg-id");
        assert_eq!(env.sender_id, "alice");
        assert_eq!(env.recipient_id, "bob");
        assert_eq!(env.message_type, MessageType::DirectMessage);
        assert!(!env.is_sealed_sender);
    }

    #[test]
    fn test_from_edit_payload_is_base64_of_ciphertext() {
        use base64::Engine;
        let ciphertext = b"opaque-encrypted-edit-bytes";
        let env = KafkaMessageEnvelope::from_edit(
            "e-id".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            "orig-id".to_string(),
            ciphertext.to_vec(),
        );

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&env.encrypted_payload)
            .expect("from_edit payload must be valid base64");
        assert_eq!(decoded, ciphertext, "payload must be base64(ciphertext)");
    }

    #[test]
    fn test_from_edit_content_hash_includes_original_id() {
        // Two edits with different original_message_ids must have different content hashes
        // even if new_message_id and ciphertext are the same.
        let env_a = KafkaMessageEnvelope::from_edit(
            "new-id".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            "original-A".to_string(),
            b"same ciphertext".to_vec(),
        );
        let env_b = KafkaMessageEnvelope::from_edit(
            "new-id".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            "original-B".to_string(),
            b"same ciphertext".to_vec(),
        );

        assert_ne!(
            env_a.content_hash, env_b.content_hash,
            "content hash must include original_message_id to prevent cross-edit collisions"
        );
    }

    // ── Serde round-trips ─────────────────────────────────────────────────────

    #[test]
    fn test_serde_edits_message_id_none_is_absent_in_json() {
        // edits_message_id has skip_serializing_if = "Option::is_none"
        // Backward compatibility: existing consumers must not break on new field.
        let env = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            message_id: "msg-1".to_string(),
            encrypted_payload: b"payload".to_vec(),
            content_type: 0,
        });

        let json = serde_json::to_string(&env).expect("serialize must succeed");
        assert!(
            !json.contains("editsMessageId"),
            "editsMessageId must be absent from JSON when None (backward compat)"
        );
    }

    #[test]
    fn test_serde_edits_message_id_some_is_present_in_json() {
        let env = KafkaMessageEnvelope::from_edit(
            "new-id".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            "original-id".to_string(),
            b"payload".to_vec(),
        );

        let json = serde_json::to_string(&env).expect("serialize must succeed");
        assert!(
            json.contains("editsMessageId"),
            "editsMessageId must be present in JSON when Some"
        );
        assert!(json.contains("original-id"));
    }

    #[test]
    fn test_serde_direct_message_round_trip() {
        let env = KafkaMessageEnvelope::new_direct_message(
            "msg-rt".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            vec![0xABu8; 32],
            7,
            "encrypted-payload".to_string(),
            "content-hash".to_string(),
        );

        let json = serde_json::to_string(&env).unwrap();
        let restored: KafkaMessageEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.message_id, env.message_id);
        assert_eq!(restored.sender_id, env.sender_id);
        assert_eq!(restored.recipient_id, env.recipient_id);
        assert_eq!(restored.message_type, env.message_type);
        assert_eq!(restored.message_number, env.message_number);
        assert!(restored.edits_message_id.is_none());
    }

    #[test]
    fn test_serde_old_message_without_edits_field_deserializes_as_none() {
        // Simulate a JSON payload from an older server that doesn't have editsMessageId.
        // Deserialization must succeed and edits_message_id must be None.
        let json = r#"{
            "messageId": "old-msg",
            "senderId": "alice",
            "recipientId": "bob",
            "timestamp": 1700000000,
            "messageType": "directMessage",
            "encryptedPayload": "cGF5bG9hZA==",
            "contentHash": "abc123",
            "cryptoSuiteId": 0,
            "federated": false,
            "isSealedSender": false
        }"#;

        let env: KafkaMessageEnvelope = serde_json::from_str(json)
            .expect("old message without editsMessageId must deserialize");
        assert!(
            env.edits_message_id.is_none(),
            "editsMessageId must default to None for old messages"
        );
    }

    #[test]
    fn test_serde_receipt_round_trip() {
        let env = KafkaMessageEnvelope::from_receipt(
            "alice".to_string(),
            "bob".to_string(),
            vec!["msg-1".to_string(), "msg-2".to_string()],
            "delivered",
        );

        let json = serde_json::to_string(&env).unwrap();
        let restored: KafkaMessageEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.message_type, MessageType::Receipt);
        assert_eq!(restored.sender_id, "alice");
        assert_eq!(restored.recipient_id, "bob");

        // The payload must be valid JSON containing message_ids and status
        let payload: serde_json::Value = serde_json::from_str(&restored.encrypted_payload)
            .expect("receipt payload must be JSON");
        assert_eq!(payload["status"], "delivered");
        let ids = payload["message_ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2);
    }

    // ── validate() ───────────────────────────────────────────────────────────

    #[test]
    fn test_validate_direct_message_passes() {
        let env = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            message_id: "msg-1".to_string(),
            encrypted_payload: b"payload".to_vec(),
            content_type: 0,
        });
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_validate_sealed_sender_passes_with_sealed_inner() {
        let env = KafkaMessageEnvelope::from_sealed_sender(
            "msg-s".to_string(),
            "bob".to_string(),
            b"sealed-inner-bytes".to_vec(),
        );
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_validate_mls_message_requires_mls_payload() {
        let mut env = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: "alice".to_string(),
            recipient_id: "group-1".to_string(),
            message_id: "mls-1".to_string(),
            encrypted_payload: b"mls-ciphertext".to_vec(),
            content_type: 0,
        });
        env.message_type = MessageType::MLSMessage;
        env.mls_payload = None; // missing required field

        assert!(
            env.validate().is_err(),
            "MLSMessage without mls_payload must fail validation"
        );
    }

    #[test]
    fn test_validate_federated_message_requires_origin_server() {
        let mut env = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            message_id: "fed-1".to_string(),
            encrypted_payload: b"payload".to_vec(),
            content_type: 0,
        });
        env.message_type = MessageType::FederatedMessage;
        env.server_signature = Some("sig".to_string());
        // origin_server still None

        assert!(
            env.validate().is_err(),
            "FederatedMessage without origin_server must fail validation"
        );
    }

    // ── DeliveryAckEvent.validate() ───────────────────────────────────────────

    #[test]
    fn test_delivery_ack_validate_requires_64_char_hashes() {
        let good_hash = "a".repeat(64);
        let short_hash = "a".repeat(32);

        let good = DeliveryAckEvent::new(
            "msg-id".to_string(),
            good_hash.clone(),
            good_hash.clone(),
            good_hash.clone(),
        );
        assert!(good.validate().is_ok());

        let bad = DeliveryAckEvent::new(
            "msg-id".to_string(),
            short_hash.clone(),
            good_hash.clone(),
            good_hash.clone(),
        );
        assert!(
            bad.validate().is_err(),
            "hash shorter than 64 chars must fail validation"
        );
    }
}
