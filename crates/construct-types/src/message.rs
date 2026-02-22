use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export types from construct-crypto
pub use construct_crypto::{EncryptedMessage, UploadableKeyBundle};

// Re-export UserId for convenience
pub use crate::user_id::UserId;

// ============================================================================
// MessageType - Distinguishes encrypted messages from control messages
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    /// Standard encrypted message (default for backward compatibility)
    #[default]
    Regular,
    /// Control message: notify peer that session was reset
    EndSession,
}

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::Regular => "REGULAR",
            MessageType::EndSession => "END_SESSION",
        }
    }
}

impl std::str::FromStr for MessageType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "REGULAR" => Ok(MessageType::Regular),
            "END_SESSION" => Ok(MessageType::EndSession),
            _ => Err(format!("Unknown message type: {}", s)),
        }
    }
}

// ============================================================================
// ChatMessage (formerly Message) - Updated for Double Ratchet Protocol
// Phase 4.5: Added MessageType to support control messages
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub id: String,
    pub from: String,
    pub to: String,

    /// Message type (Regular or EndSession)
    /// Default: Regular for backward compatibility
    #[serde(default, rename = "type")]
    pub message_type: MessageType,

    /// Ephemeral public key for DH ratchet (32 bytes raw bytes)
    /// Serialized as MessagePack bin format
    /// REQUIRED for Regular messages, MUST be None for EndSession
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "serde_bytes_option")]
    pub ephemeral_public_key: Option<Vec<u8>>,

    /// Message number in symmetric-key ratchet chain
    /// Used for out-of-order message handling and forward secrecy
    /// REQUIRED for Regular messages, MUST be None for EndSession
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    /// Base64-encoded ChaChaPoly sealed box
    /// Contains: nonce (12 bytes) + ciphertext (variable) + tag (16 bytes)
    /// The nonce field is now REMOVED (included in sealed box)
    /// REQUIRED for Regular messages, MUST be None for EndSession
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Unix timestamp in seconds (client-side timestamp)
    pub timestamp: u64,
}

// Helper module for Option<Vec<u8>> with serde_bytes
mod serde_bytes_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
            .map(|opt| opt.map(|buf| buf.into_vec()))
    }
}

#[allow(dead_code)]
impl ChatMessage {
    /// Create new regular encrypted message
    pub fn new(
        from: String,
        to: String,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        content: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            message_type: MessageType::Regular,
            ephemeral_public_key: Some(ephemeral_public_key),
            message_number: Some(message_number),
            content: Some(content),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// Create new END_SESSION control message
    pub fn new_end_session(from: String, to: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            message_type: MessageType::EndSession,
            ephemeral_public_key: None,
            message_number: None,
            content: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// Validate message structure based on type
    pub fn is_valid(&self) -> bool {
        // Basic validation
        if self.from.is_empty()
            || self.to.is_empty()
            || Uuid::parse_str(&self.id).is_err()
            || UserId::parse(&self.from).is_err()
            || UserId::parse(&self.to).is_err()
        {
            return false;
        }

        // Type-specific validation
        match self.message_type {
            MessageType::Regular => {
                // Regular messages MUST have all encryption fields
                self.ephemeral_public_key
                    .as_ref()
                    .map(|k| k.len() == 32)
                    .unwrap_or(false)
                    && self.message_number.is_some()
                    && self
                        .content
                        .as_ref()
                        .map(|c| !c.is_empty())
                        .unwrap_or(false)
            }
            MessageType::EndSession => {
                // END_SESSION messages MUST NOT have encryption fields
                self.ephemeral_public_key.is_none()
                    && self.message_number.is_none()
                    && self.content.is_none()
            }
        }
    }
}

// ============================================================================
// Client Message Data Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    pub username: String,
    pub password: String,
    /// Native UploadableKeyBundle structure (MessagePack serialized)
    pub public_key: UploadableKeyBundle,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectData {
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyData {
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatePrekeyData {
    pub user_id: String,
    /// Native UploadableKeyBundle structure (MessagePack serialized)
    pub update: UploadableKeyBundle,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutData {
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceTokenData {
    /// APNs device token (hex string)
    pub device_token: String,
    /// Optional device name for user identification
    pub device_name: Option<String>,
    /// Notification filter preference
    pub notification_filter: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnregisterDeviceTokenData {
    /// APNs device token to remove
    pub device_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDeviceTokenPreferencesData {
    /// Device token to update
    pub device_token: String,
    /// New notification filter
    pub notification_filter: String,
    /// Whether push is enabled for this device
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordData {
    pub session_token: String,
    pub old_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeMessageData {
    /// Message ID being acknowledged
    pub message_id: String,

    /// Acknowledgment status
    /// Expected: "delivered"
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountData {
    pub session_token: String,
    pub password: String,
}

// ============================================================================
// Media Upload Token Request/Response
// ============================================================================

/// Request for media upload token
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMediaTokenData {
    /// Request ID for correlation
    pub request_id: String,
}

/// Dummy message for traffic analysis protection
/// Server will ignore these messages but they help mask real traffic patterns
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DummyMessageData {
    /// Base64-encoded random bytes
    pub payload: String,
}

// ============================================================================
// Phase 4.5: END_SESSION Control Message Data
// ============================================================================

/// Request to end session with a peer
/// Sent before app reinstall or manual session reset
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndSessionData {
    /// Recipient user ID (who should archive the session)
    pub recipient_id: String,

    /// Optional reason for session reset (for logging/debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ============================================================================
// ClientMessage Enum - Internally Tagged Format
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[serde(rename_all = "camelCase")]
pub enum ClientMessage {
    Register(RegisterData),
    Login(LoginData),
    Connect(ConnectData),
    GetPublicKey(GetPublicKeyData),
    SendMessage(ChatMessage),
    AcknowledgeMessage(AcknowledgeMessageData),
    RotatePrekey(RotatePrekeyData),
    ChangePassword(ChangePasswordData),
    Logout(LogoutData),
    DeleteAccount(DeleteAccountData),
    RegisterDeviceToken(RegisterDeviceTokenData),
    UnregisterDeviceToken(UnregisterDeviceTokenData),
    UpdateDeviceTokenPreferences(UpdateDeviceTokenPreferencesData),
    RequestMediaToken(RequestMediaTokenData),
    Dummy(DummyMessageData), // Traffic protection: dummy message (ignored by server)
    EndSession(EndSessionData), // Phase 4.5: Control message to end session
}

// ============================================================================
// Server Message Data Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSuccessData {
    pub user_id: String,
    pub username: String,
    pub session_token: String,
    pub expires: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginSuccessData {
    pub user_id: String,
    pub username: String,
    pub session_token: String,
    pub expires: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectSuccessData {
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyBundleData {
    pub user_id: String,
    /// Username of the user (for display purposes, shared during key exchange)
    pub username: String,
    /// Base64-encoded X25519 identity public key (32 bytes)
    pub identity_public: String,
    /// Base64-encoded X25519 signed prekey public key (32 bytes)
    pub signed_prekey_public: String,
    /// Base64-encoded Ed25519 signature (64 bytes)
    pub signature: String,
    /// Base64-encoded Ed25519 verifying key (32 bytes)
    pub verifying_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckData {
    pub message_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorData {
    pub code: String,
    pub message: String,
}

// EncryptedMessage re-exported at the top from construct-crypto

// ============================================================================
// Phase 4.5: SessionEnded Server Message Data
// ============================================================================

/// Notification that peer has ended the session
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEndedData {
    /// User ID who ended the session
    pub from_user_id: String,

    /// When the session was ended (ISO 8601 timestamp)
    pub timestamp: String,

    /// Optional reason for session reset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ============================================================================
// ServerMessage Enum - Internally Tagged Format
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[serde(rename_all = "camelCase")]
pub enum ServerMessage {
    RegisterSuccess(RegisterSuccessData),
    LoginSuccess(LoginSuccessData),
    ConnectSuccess(ConnectSuccessData),
    SessionExpired,
    PublicKeyBundle(PublicKeyBundleData),
    Message(ChatMessage),
    EncryptedMessage(EncryptedMessage), // Encrypted message (Double Ratchet protocol)
    Ack(AckData),
    KeyRotationSuccess,
    ChangePasswordSuccess,
    Error(ErrorData),
    LogoutSuccess,
    DeleteAccountSuccess,
    DeviceTokenRegistered,
    DeviceTokenUnregistered,
    DeviceTokenPreferencesUpdated,
    SessionEnded(SessionEndedData), // Phase 4.5: Notify peer that session was reset
}

// ============================================================================
// Tests - Verify MessagePack Format
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_message_internally_tagged_format() {
        let msg = ServerMessage::RegisterSuccess(RegisterSuccessData {
            user_id: "test-id".to_string(),
            username: "test".to_string(),
            session_token: "token".to_string(),
            expires: 1234567890,
        });

        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();

        // Должно начинаться с 0x82 (map{2}) а не 0x92 (array[2])
        assert_eq!(
            bytes[0], 0x82,
            "First byte должен быть 0x82 (map), got 0x{:02x}",
            bytes[0]
        );

        // Декодируем обратно чтобы убедиться что структура правильная
        let decoded: ServerMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            ServerMessage::RegisterSuccess(data) => {
                assert_eq!(data.user_id, "test-id");
                assert_eq!(data.username, "test");
            }
            _ => panic!("Wrong variant decoded"),
        }

        // Проверяем что в байтах есть "type" и "payload" ключи
        let hex = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // "type" = 74 79 70 65 в hex
        assert!(hex.contains("74797065"), "Should contain 'type' key");
        // "payload" = 70 61 79 6c 6f 61 64 в hex
        assert!(
            hex.contains("7061796c6f6164"),
            "Should contain 'payload' key"
        );
    }

    #[test]
    fn test_server_message_unit_variant_format() {
        let msg = ServerMessage::SessionExpired;
        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();

        // Unit variant должен быть map{1} с только "type"
        assert_eq!(
            bytes[0], 0x81,
            "Unit variant should be 0x81 (map{{1}}), got 0x{:02x}",
            bytes[0]
        );

        // Декодируем обратно
        let decoded: ServerMessage = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ServerMessage::SessionExpired));
    }

    #[test]
    fn test_client_message_internally_tagged_format() {
        let msg = ClientMessage::Login(LoginData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();

        // Должно начинаться с 0x82 (map{2})
        assert_eq!(
            bytes[0], 0x82,
            "ClientMessage should be 0x82 (map), got 0x{:02x}",
            bytes[0]
        );

        // Декодируем обратно
        let decoded: ClientMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            ClientMessage::Login(data) => {
                assert_eq!(data.username, "testuser");
                assert_eq!(data.password, "testpass");
            }
            _ => panic!("Wrong variant decoded"),
        }
    }

    // ========================================================================
    // Phase 4.5: END_SESSION Protocol Tests
    // ========================================================================

    #[test]
    fn test_message_type_serialization() {
        // Regular
        let regular = MessageType::Regular;
        assert_eq!(regular.as_str(), "REGULAR");

        // EndSession
        let end_session = MessageType::EndSession;
        assert_eq!(end_session.as_str(), "END_SESSION");

        // Default
        let default = MessageType::default();
        assert_eq!(default, MessageType::Regular);
    }

    #[test]
    fn test_message_type_from_str() {
        use std::str::FromStr;

        assert_eq!(
            MessageType::from_str("REGULAR").unwrap(),
            MessageType::Regular
        );
        assert_eq!(
            MessageType::from_str("END_SESSION").unwrap(),
            MessageType::EndSession
        );
        assert!(MessageType::from_str("UNKNOWN").is_err());
    }

    #[test]
    fn test_chat_message_regular_validation() {
        // Valid regular message
        let valid_msg = ChatMessage::new(
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
            vec![0u8; 32],
            0,
            "encrypted_content".to_string(),
        );
        assert!(valid_msg.is_valid());
        assert_eq!(valid_msg.message_type, MessageType::Regular);

        // Invalid: missing ephemeral_public_key
        let mut invalid = valid_msg.clone();
        invalid.ephemeral_public_key = None;
        assert!(!invalid.is_valid());

        // Invalid: wrong ephemeral_public_key length
        let mut invalid = valid_msg.clone();
        invalid.ephemeral_public_key = Some(vec![0u8; 16]);
        assert!(!invalid.is_valid());

        // Invalid: missing message_number
        let mut invalid = valid_msg.clone();
        invalid.message_number = None;
        assert!(!invalid.is_valid());

        // Invalid: missing content
        let mut invalid = valid_msg;
        invalid.content = None;
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_chat_message_end_session_validation() {
        // Valid END_SESSION message
        let valid_end_session =
            ChatMessage::new_end_session(Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
        assert!(valid_end_session.is_valid());
        assert_eq!(valid_end_session.message_type, MessageType::EndSession);
        assert!(valid_end_session.ephemeral_public_key.is_none());
        assert!(valid_end_session.message_number.is_none());
        assert!(valid_end_session.content.is_none());

        // Invalid: END_SESSION with ephemeral_public_key
        let mut invalid = valid_end_session.clone();
        invalid.ephemeral_public_key = Some(vec![0u8; 32]);
        assert!(!invalid.is_valid());

        // Invalid: END_SESSION with message_number
        let mut invalid = valid_end_session.clone();
        invalid.message_number = Some(0);
        assert!(!invalid.is_valid());

        // Invalid: END_SESSION with content
        let mut invalid = valid_end_session;
        invalid.content = Some("content".to_string());
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_chat_message_backward_compatibility() {
        // Message without type field should default to Regular
        let json = r#"{"id":"123","from":"alice","to":"bob","ephemeralPublicKey":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],"messageNumber":0,"content":"test","timestamp":1234567890}"#;

        let msg: ChatMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, MessageType::Regular);
    }

    #[test]
    fn test_end_session_client_message() {
        let msg = ClientMessage::EndSession(EndSessionData {
            recipient_id: Uuid::new_v4().to_string(),
            reason: Some("app_reinstall".to_string()),
        });

        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();
        let decoded: ClientMessage = rmp_serde::from_slice(&bytes).unwrap();

        match decoded {
            ClientMessage::EndSession(data) => {
                assert_eq!(data.reason, Some("app_reinstall".to_string()));
            }
            _ => panic!("Wrong variant decoded"),
        }
    }

    #[test]
    fn test_session_ended_server_message() {
        let msg = ServerMessage::SessionEnded(SessionEndedData {
            from_user_id: Uuid::new_v4().to_string(),
            timestamp: "2026-01-27T13:00:00Z".to_string(),
            reason: Some("app_reinstall".to_string()),
        });

        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();
        let decoded: ServerMessage = rmp_serde::from_slice(&bytes).unwrap();

        match decoded {
            ServerMessage::SessionEnded(data) => {
                assert_eq!(data.timestamp, "2026-01-27T13:00:00Z");
                assert_eq!(data.reason, Some("app_reinstall".to_string()));
            }
            _ => panic!("Wrong variant decoded"),
        }
    }
}
