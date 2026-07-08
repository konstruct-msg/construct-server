use serde::{Deserialize, Serialize};

/// Push notification type according to notification-philosophy.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushType {
    /// Silent push - wakes app without notification (Phase 1)
    Silent,
    /// Visible push - shows notification to user (Phase 2)
    Visible,
    /// VoIP push (PushKit) — incoming calls wake-up
    Voip,
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
///
/// SECURITY: the entire payload is constructed by the server and visible to
/// Apple/APNs. It MUST only be used for OS wake-up / CallKit UI hints. The
/// client MUST verify all call state (caller identity, call id, fingerprints)
/// against its own E2EE signaling state and MUST NOT accept a call solely
/// because this payload arrived.
#[derive(Debug, Clone, Serialize)]
pub struct ApnsPayload {
    pub aps: ApsData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub construct: Option<ConstructData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "construct_call")]
    pub construct_call: Option<ConstructCallData>,
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

/// VoIP call metadata attached to a PushKit push.
///
/// SECURITY: this data is server-visible. `caller_id`/`caller_name` are only
/// hints for CallKit. The recipient client MUST confirm the caller and call
/// details through the E2EE signaling path before trusting them.
#[derive(Debug, Clone, Serialize)]
pub struct ConstructCallData {
    pub call_id: String,
    pub caller_id: String,
    pub caller_name: String,
    pub call_type: String,
    pub offered_at: i64,
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
            construct_call: None,
        }
    }

    /// Create key-rotation wake push (Phase 3B).
    ///
    /// Silent background push that tells the device to rotate its Signed Pre-Key
    /// and replenish one-time pre-keys. No sender identity or conversation context.
    /// Privacy: cannot be distinguished from a regular silent push by an observer.
    pub fn key_rotation_wake() -> Self {
        Self {
            aps: ApsData {
                content_available: Some(1),
                alert: None,
                sound: None,
                badge: None,
            },
            construct: Some(ConstructData {
                notification_type: "rotate_keys".to_string(),
                conversation_id: None,
            }),
            construct_call: None,
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
            construct_call: None,
        }
    }

    /// Create VoIP push (incoming call).
    ///
    /// Privacy: Only includes call metadata needed for CallKit, no content.
    pub fn voip_incoming_call(
        call_id: String,
        caller_id: String,
        caller_name: String,
        call_type: String,
        offered_at: i64,
    ) -> Self {
        Self {
            aps: ApsData {
                content_available: None,
                alert: None,
                sound: None,
                badge: None,
            },
            construct: None,
            construct_call: Some(ConstructCallData {
                call_id,
                caller_id,
                caller_name,
                call_type,
                offered_at,
            }),
        }
    }
}
