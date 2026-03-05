use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Delivery pending record stored in database
/// Contains anonymized message → sender mapping using HMAC
#[derive(Debug, Clone)]
pub struct DeliveryPending {
    /// HMAC-SHA256 hash of message ID
    /// Format: hex string (64 characters)
    pub message_hash: String,

    /// Sender's user ID (UUID string)
    /// Stored in plaintext to enable ACK routing
    pub sender_id: String,

    /// Expiration timestamp (UTC)
    /// Records older than this are automatically cleaned up
    pub expires_at: DateTime<Utc>,

    /// Creation timestamp (UTC)
    /// Used for audit/debugging
    pub created_at: DateTime<Utc>,
}

/// Data structure for client acknowledge message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeMessageData {
    /// Message ID being acknowledged
    pub message_id: String,

    /// Acknowledgment status
    /// Expected: "delivered"
    pub status: String,
}

impl DeliveryPending {
    pub fn new(message_hash: String, sender_id: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            message_hash,
            sender_id,
            expires_at,
            created_at: Utc::now(),
        }
    }
}
