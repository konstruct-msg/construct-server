use anyhow::Context;
use anyhow::Result;
use apns_h2::{
    Client, ClientConfig, DefaultNotificationBuilder, Endpoint, NotificationBuilder,
    NotificationOptions, Priority, PushType as ApnsPushType, error::Error as ApnsH2Error,
    response::ErrorReason,
};
use hex;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::types::{ApnsPayload, NotificationPriority, PushType};
use construct_config::{ApnsConfig, ApnsEnvironment};

/// Error type returned by APNs send operations.
///
/// Callers MUST handle `InvalidToken` by disabling the token in the database —
/// APNs will never accept it again until the device re-registers.
#[derive(Debug, Error)]
pub enum ApnsSendError {
    /// APNs rejected the device token (`BadDeviceToken` or `Unregistered`).
    ///
    /// The token is permanently invalid. Caller should set `enabled = false`
    /// on the `device_tokens` row so we stop hammering APNs with dead tokens.
    #[error("APNs: device token is invalid or unregistered")]
    InvalidToken,

    /// Any other APNs or infrastructure error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// APNs client wrapper
#[derive(Clone)]
pub struct ApnsClient {
    client: Arc<RwLock<Option<Client>>>,
    config: ApnsConfig,
}

impl ApnsClient {
    /// Create new APNs client
    pub fn new(config: ApnsConfig) -> Result<Self> {
        Ok(Self {
            client: Arc::new(RwLock::new(None)),
            config,
        })
    }

    /// Initialize APNs client (loads key from file)
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("APNs is disabled - skipping initialization");
            return Ok(());
        }

        info!(
            "Initializing APNs client (environment: {:?})",
            self.config.environment
        );

        // Open .p8 key file
        let key_file = File::open(&self.config.key_path)
            .with_context(|| format!("Failed to open APNs key file: {}", self.config.key_path))?;
        let mut key_reader = BufReader::new(key_file);

        // Determine endpoint (production or sandbox)
        let endpoint = match self.config.environment {
            ApnsEnvironment::Production => Endpoint::Production,
            ApnsEnvironment::Development => Endpoint::Sandbox,
        };

        let client_config = ClientConfig::new(endpoint);

        // Create client using token-based authentication
        let client = Client::token(
            &mut key_reader,
            &self.config.key_id,
            &self.config.team_id,
            client_config,
        )
        .with_context(|| "Failed to create APNs client")?;

        *self.client.write().await = Some(client);

        info!(
            "APNs client initialized successfully (key_id: {}, team_id: {})",
            self.config.key_id, self.config.team_id
        );

        Ok(())
    }

    /// Send push notification to device.
    ///
    /// Returns `Err(ApnsSendError::InvalidToken)` when APNs signals the token is
    /// permanently invalid — caller should disable it in the database.
    pub async fn send_notification(
        &self,
        device_token: &str,
        payload: ApnsPayload,
        push_type: PushType,
        priority: NotificationPriority,
    ) -> Result<(), ApnsSendError> {
        if !self.config.enabled {
            debug!("APNs disabled - skipping notification send");
            return Ok(());
        }

        let client_guard = self.client.read().await;
        let client = client_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("APNs client not initialized"))?;

        // Serialize payload
        let payload_json =
            serde_json::to_string(&payload).with_context(|| "Failed to serialize APNs payload")?;

        // SECURITY: Hash device token for logging (never log full token)
        use crate::DeviceTokenEncryption;
        let token_hash_bytes = DeviceTokenEncryption::hash_token(device_token);
        let token_hash_hex = hex::encode(&token_hash_bytes);
        debug!(
            "Sending APNs notification: device_token_hash={}, push_type={:?}, priority={:?}",
            &token_hash_hex[..8],
            push_type,
            priority
        );
        debug!("APNs payload: {}", payload_json);

        let topic = match push_type {
            PushType::Voip => self
                .config
                .voip_topic
                .as_deref()
                .unwrap_or(&self.config.topic),
            _ => &self.config.topic,
        };

        // Create notification options
        // apns-push-type is REQUIRED since iOS 13 — missing it causes silent drops
        let options = NotificationOptions {
            apns_topic: Some(topic),
            apns_push_type: Some(match push_type {
                PushType::Silent => ApnsPushType::Background,
                PushType::Visible => ApnsPushType::Alert,
                PushType::Voip => ApnsPushType::Voip,
            }),
            apns_priority: Some(match push_type {
                PushType::Voip => Priority::High,
                _ => match priority {
                    NotificationPriority::High => Priority::High,
                    NotificationPriority::Low => Priority::Normal,
                },
            }),
            apns_expiration: match push_type {
                // Calls: do not store / retry when device is offline.
                PushType::Voip => Some(0),
                _ => None,
            },
            ..Default::default()
        };

        // Build notification based on push type.
        // BUG FIX: previously the `payload` parameter was ignored entirely and
        // a hardcoded DefaultNotificationBuilder was used for all cases.
        let mut built = match push_type {
            PushType::Silent => {
                // Background push: content-available = 1, no alert, no sound
                DefaultNotificationBuilder::new()
                    .content_available()
                    .build(device_token, options)
            }
            PushType::Visible => {
                // Use alert title/body from payload; fall back to generic strings (privacy-safe).
                let (title, body) = if let Some(ref alert) = payload.aps.alert {
                    (alert.title.as_str(), alert.body.as_str())
                } else {
                    ("Construct", "New message")
                };
                let sound = payload.aps.sound.as_deref().unwrap_or("default");
                let mut builder = DefaultNotificationBuilder::new()
                    .title(title)
                    .body(body)
                    .sound(sound)
                    .content_available() // wake app even for visible alerts (lock screen + killed)
                    .mutable_content(); // lets iOS notification extension process it in foreground
                if let Some(badge) = payload.aps.badge {
                    builder = builder.badge(badge);
                }
                builder.build(device_token, options)
            }
            PushType::Voip => DefaultNotificationBuilder::new().build(device_token, options),
        };

        // Attach our custom `construct` metadata so the iOS app knows message type / conversation
        if let Some(ref construct_data) = payload.construct
            && let Err(e) = built.add_custom_data("construct", construct_data)
        {
            warn!("Failed to attach custom APNs data: {}", e);
        }

        if let Some(ref call_data) = payload.construct_call
            && let Err(e) = built.add_custom_data("construct_call", call_data)
        {
            warn!("Failed to attach custom APNs call data: {}", e);
        }

        // Send notification
        match client.send(built).await {
            Ok(_response) => {
                debug!("APNs notification sent successfully");
                Ok(())
            }
            Err(e) => {
                // Detect permanently-invalid tokens so callers can disable them in the DB.
                // BadDeviceToken  → token format wrong or environment mismatch
                // Unregistered    → app was uninstalled, token no longer exists
                let is_invalid_token = if let ApnsH2Error::ResponseError(ref resp) = e {
                    resp.error
                        .as_ref()
                        .map(|body| {
                            matches!(
                                body.reason,
                                ErrorReason::BadDeviceToken | ErrorReason::Unregistered
                            )
                        })
                        .unwrap_or(false)
                } else {
                    false
                };

                error!("Failed to send APNs notification: {:?}", e);
                warn!("APNs error: {}", e);

                if is_invalid_token {
                    return Err(ApnsSendError::InvalidToken);
                }
                Err(anyhow::anyhow!(e).into())
            }
        }
    }

    /// Send silent push notification (background wake-up, no visible alert).
    ///
    /// Returns `Err(ApnsSendError::InvalidToken)` if the token is dead — caller
    /// should disable it in the database.
    pub async fn send_silent_push(
        &self,
        device_token: &str,
        conversation_id: Option<String>,
    ) -> Result<(), ApnsSendError> {
        let payload = ApnsPayload::silent(conversation_id);
        self.send_notification(
            device_token,
            payload,
            PushType::Silent,
            NotificationPriority::Low,
        )
        .await
    }

    /// Send visible push notification (shows alert banner).
    ///
    /// Returns `Err(ApnsSendError::InvalidToken)` if the token is dead — caller
    /// should disable it in the database.
    pub async fn send_visible_push(
        &self,
        device_token: &str,
        sender_name: &str,
        conversation_id: Option<String>,
    ) -> Result<(), ApnsSendError> {
        let payload = ApnsPayload::visible(sender_name, conversation_id);
        self.send_notification(
            device_token,
            payload,
            PushType::Visible,
            NotificationPriority::High,
        )
        .await
    }

    /// Send VoIP push notification (incoming call wake-up).
    ///
    /// Requires `APNS_VOIP_TOPIC` (or `APNS_VOIP_BUNDLE_ID`) to be set.
    pub async fn send_voip_incoming_call_push(
        &self,
        device_token: &str,
        call_id: String,
        caller_id: String,
        caller_name: String,
        call_type: String,
        offered_at: i64,
    ) -> Result<(), ApnsSendError> {
        if self.config.voip_topic.as_deref().unwrap_or("").is_empty() {
            // Explicitly skip — we don't want to send a VoIP push with the normal topic,
            // which APNs would reject.
            debug!("APNs VoIP topic is not configured - skipping VoIP push send");
            return Ok(());
        }

        let payload =
            ApnsPayload::voip_incoming_call(call_id, caller_id, caller_name, call_type, offered_at);
        self.send_notification(
            device_token,
            payload,
            PushType::Voip,
            NotificationPriority::High,
        )
        .await
    }

    /// Check if APNs is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}
