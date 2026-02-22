// ============================================================================
// Pending Messages Types
// ============================================================================

use serde::{Deserialize, Serialize};

/// Message status in 2-phase commit protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageStatus {
    /// Phase 1 complete: Message written to Kafka, awaiting client confirmation
    Pending,

    /// Phase 2 complete: Client confirmed receipt, or auto-confirmed by worker
    Confirmed,

    /// Message delivered to recipient (optional tracking)
    Delivered,
}

impl MessageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "PENDING",
            MessageStatus::Confirmed => "CONFIRMED",
            MessageStatus::Delivered => "DELIVERED",
        }
    }
}

impl std::str::FromStr for MessageStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PENDING" => Ok(MessageStatus::Pending),
            "CONFIRMED" => Ok(MessageStatus::Confirmed),
            "DELIVERED" => Ok(MessageStatus::Delivered),
            _ => Err(()),
        }
    }
}

/// Pending message data stored in Redis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessageData {
    /// Temporary ID provided by client (for idempotency)
    pub temp_id: String,

    /// Actual message ID assigned by server (written to Kafka)
    pub message_id: String,

    /// Sender user ID
    pub sender_id: String,

    /// Recipient user ID
    pub recipient_id: String,

    /// Current status in state machine
    pub status: MessageStatus,

    /// Unix timestamp when message was created (Phase 1)
    pub created_at: i64,

    /// Unix timestamp when message was confirmed (Phase 2), if confirmed
    pub confirmed_at: Option<i64>,

    /// Kafka partition the message was written to
    pub kafka_partition: Option<i32>,

    /// Kafka offset within the partition
    pub kafka_offset: Option<i64>,
}

impl PendingMessageData {
    pub fn new(
        temp_id: String,
        message_id: String,
        sender_id: String,
        recipient_id: String,
    ) -> Self {
        Self {
            temp_id,
            message_id,
            sender_id,
            recipient_id,
            status: MessageStatus::Pending,
            created_at: chrono::Utc::now().timestamp(),
            confirmed_at: None,
            kafka_partition: None,
            kafka_offset: None,
        }
    }

    /// Mark as confirmed (Phase 2)
    pub fn confirm(&mut self) {
        self.status = MessageStatus::Confirmed;
        self.confirmed_at = Some(chrono::Utc::now().timestamp());
    }

    /// Check if message is expired (for cleanup)
    pub fn is_expired(&self, max_age_seconds: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        (now - self.created_at) > max_age_seconds
    }

    /// Check if message should be auto-confirmed
    pub fn should_auto_confirm(&self, auto_confirm_after_seconds: i64) -> bool {
        if self.status != MessageStatus::Pending {
            return false;
        }

        let now = chrono::Utc::now().timestamp();
        (now - self.created_at) >= auto_confirm_after_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_status_serialization() {
        assert_eq!(MessageStatus::Pending.as_str(), "PENDING");
        assert_eq!(MessageStatus::Confirmed.as_str(), "CONFIRMED");
        assert_eq!(MessageStatus::Delivered.as_str(), "DELIVERED");

        assert_eq!(
            "PENDING".parse::<MessageStatus>(),
            Ok(MessageStatus::Pending)
        );
        assert_eq!(
            "CONFIRMED".parse::<MessageStatus>(),
            Ok(MessageStatus::Confirmed)
        );
        assert!("INVALID".parse::<MessageStatus>().is_err());
    }

    #[test]
    fn test_pending_message_lifecycle() {
        let mut msg = PendingMessageData::new(
            "temp-123".to_string(),
            "msg-456".to_string(),
            "user-a".to_string(),
            "user-b".to_string(),
        );

        assert_eq!(msg.status, MessageStatus::Pending);
        assert!(msg.confirmed_at.is_none());

        msg.confirm();

        assert_eq!(msg.status, MessageStatus::Confirmed);
        assert!(msg.confirmed_at.is_some());
    }

    #[test]
    fn test_auto_confirm_logic() {
        let mut msg = PendingMessageData::new(
            "temp-123".to_string(),
            "msg-456".to_string(),
            "user-a".to_string(),
            "user-b".to_string(),
        );

        // Just created, should not auto-confirm
        assert!(!msg.should_auto_confirm(300)); // 5 minutes

        // Simulate 6 minutes ago
        msg.created_at = chrono::Utc::now().timestamp() - 360;
        assert!(msg.should_auto_confirm(300)); // Should auto-confirm

        // Already confirmed, should not auto-confirm
        msg.confirm();
        assert!(!msg.should_auto_confirm(300));
    }

    #[test]
    fn test_expiration_logic() {
        let mut msg = PendingMessageData::new(
            "temp-123".to_string(),
            "msg-456".to_string(),
            "user-a".to_string(),
            "user-b".to_string(),
        );

        // Just created, not expired
        assert!(!msg.is_expired(1800)); // 30 minutes

        // Simulate 35 minutes ago
        msg.created_at = chrono::Utc::now().timestamp() - 2100;
        assert!(msg.is_expired(1800)); // Expired
    }
}
