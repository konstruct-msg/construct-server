use serde::{Deserialize, Serialize};

/// Push notification type according to notification-philosophy.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushType {
    /// Silent push - wakes app without notification (Phase 1)
    Silent,
    /// Visible push - shows notification to user (Phase 2)
    Visible,
}

/// Notification priority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationPriority {
    /// Send immediately (for visible notifications)
    High,
    /// Power-efficient delivery (for silent notifications)
    Low,
}

/// Notification filter level (Phase 2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NotificationFilter {
    /// All messages trigger notifications
    All,
    /// Only direct 1-on-1 messages
    DirectMessagesOnly,
    /// Only @mentions in groups
    MentionsOnly,
    /// Only messages from contacts
    FromContactsOnly,
}

/// APNs payload structure
#[derive(Debug, Clone, Serialize)]
pub struct ApnsPayload {
    pub aps: ApsData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub construct: Option<ConstructData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApsData {
    /// For silent push: content-available = 1
    /// For visible push: alert with title/body
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "content-available")]
    pub content_available: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<AlertData>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sound: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertData {
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConstructData {
    #[serde(rename = "type")]
    pub notification_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
}

impl ApnsPayload {
    /// Create silent push notification (Phase 1: Option B from docs)
    /// Wakes app in background, no user-visible notification
    pub fn silent(conversation_id: Option<String>) -> Self {
        Self {
            aps: ApsData {
                content_available: Some(1),
                alert: None,
                sound: None,
                badge: None,
            },
            construct: Some(ConstructData {
                notification_type: "new_message".to_string(),
                conversation_id,
            }),
        }
    }

    /// Create visible push notification (Phase 2: Option C from docs)
    /// Shows notification to user
    /// IMPORTANT: Never include message content in payload! (privacy)
    pub fn visible(sender_name: &str, conversation_id: Option<String>) -> Self {
        Self {
            aps: ApsData {
                content_available: None,
                alert: Some(AlertData {
                    title: sender_name.to_string(),
                    body: "New message".to_string(), // Generic, no content!
                }),
                sound: Some("default".to_string()),
                badge: Some(1),
            },
            construct: Some(ConstructData {
                notification_type: "new_message".to_string(),
                conversation_id,
            }),
        }
    }
}
