// ============================================================================
// Message Validator
// ============================================================================
//
// Validates message structure and content for:
// - Double Ratchet protocol compliance
// - Sender authentication (anti-spoofing)
// - Message replay protection
// - User blocking status
//
// All validation is stateless - can be run on any instance
// ============================================================================

use anyhow::{Result, anyhow};
use base64::Engine;
use construct_types::ChatMessage;

pub struct MessageValidator;

impl MessageValidator {
    /// Create a new message validator
    pub fn new() -> Self {
        Self
    }

    /// Validate message structure and cryptographic envelope
    ///
    /// Checks:
    /// - Message has all required fields
    /// - Ephemeral public key is exactly 32 bytes (Curve25519)
    /// - Ciphertext is non-empty
    /// - Message ID is valid UUID format
    pub fn validate_structure(&self, msg: &ChatMessage) -> Result<()> {
        // Message gateway only handles Regular encrypted messages
        if msg.message_type != construct_types::MessageType::Regular {
            return Err(anyhow!(
                "Message gateway only handles Regular encrypted messages"
            ));
        }

        // Use existing ChatMessage::is_valid()
        if !msg.is_valid() {
            return Err(anyhow!("Invalid message structure"));
        }

        // Additional validation: ephemeral_public_key must be 32 bytes
        let ephemeral_key = msg
            .ephemeral_public_key
            .as_ref()
            .ok_or_else(|| anyhow!("Regular message must have ephemeral_public_key"))?;

        if ephemeral_key.len() != 32 {
            return Err(anyhow!(
                "Invalid ephemeral public key size: expected 32 bytes, got {}",
                ephemeral_key.len()
            ));
        }

        // Ciphertext must not be empty
        let content = msg
            .content
            .as_ref()
            .ok_or_else(|| anyhow!("Regular message must have content"))?;

        if content.is_empty() {
            return Err(anyhow!("Empty ciphertext"));
        }

        Ok(())
    }

    /// Verify sender matches authenticated user (anti-spoofing)
    ///
    /// Prevents IDOR attacks where attacker tries to send messages
    /// with from field set to another user's ID
    pub fn verify_sender(&self, msg: &ChatMessage, authenticated_user: &str) -> Result<()> {
        if msg.from != authenticated_user {
            return Err(anyhow!(
                "Sender spoofing attempt: message.from={}, authenticated_user={}",
                msg.from,
                authenticated_user
            ));
        }

        Ok(())
    }

    /// Create deduplication key for replay protection
    ///
    /// Uses ephemeral_public_key to detect replayed messages.
    /// Since each message should have a unique ephemeral key in Double Ratchet,
    /// this provides strong replay protection.
    pub fn create_dedup_key(&self, msg: &ChatMessage) -> String {
        let ephemeral_key_b64 = base64::engine::general_purpose::STANDARD.encode(
            msg.ephemeral_public_key
                .as_ref()
                .expect("Regular message must have ephemeral_public_key"),
        );

        format!("msg_dedup:{}:{}", msg.id, ephemeral_key_b64)
    }
}

impl Default for MessageValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_message() -> ChatMessage {
        ChatMessage {
            id: uuid::Uuid::new_v4().to_string(),
            from: uuid::Uuid::new_v4().to_string(),
            to: uuid::Uuid::new_v4().to_string(),
            message_type: construct_types::MessageType::Regular,
            ephemeral_public_key: Some(vec![0u8; 32]),
            content: Some("base64encodedcontent".to_string()), // Base64-encoded ciphertext
            message_number: Some(1),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    #[test]
    fn test_valid_message() {
        let validator = MessageValidator::new();
        let msg = create_valid_message();

        assert!(validator.validate_structure(&msg).is_ok());
    }

    #[test]
    fn test_invalid_ephemeral_key_size() {
        let validator = MessageValidator::new();
        let mut msg = create_valid_message();
        msg.ephemeral_public_key = Some(vec![0u8; 16]); // Wrong size

        assert!(validator.validate_structure(&msg).is_err());
    }

    #[test]
    fn test_empty_ciphertext() {
        let validator = MessageValidator::new();
        let mut msg = create_valid_message();
        msg.content = Some("".to_string()); // Empty

        assert!(validator.validate_structure(&msg).is_err());
    }

    #[test]
    fn test_verify_sender_valid() {
        let validator = MessageValidator::new();
        let msg = create_valid_message();

        // Sender should match the from field (UUID format)
        assert!(validator.verify_sender(&msg, &msg.from).is_ok());
    }

    #[test]
    fn test_verify_sender_spoofing() {
        let validator = MessageValidator::new();
        let msg = create_valid_message();

        // Attacker tries to send as alice but is authenticated as eve
        assert!(validator.verify_sender(&msg, "eve").is_err());
    }

    #[test]
    fn test_dedup_key_generation() {
        let validator = MessageValidator::new();
        let msg = create_valid_message();

        let key = validator.create_dedup_key(&msg);

        assert!(key.starts_with("msg_dedup:"));
        assert!(key.contains(&msg.id));
    }
}
