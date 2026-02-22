use anyhow::{Context, Result};
use apns_h2::{
    Client, ClientConfig, DefaultNotificationBuilder, Endpoint, NotificationBuilder,
    NotificationOptions, Priority,
};
use hex;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::types::{ApnsPayload, NotificationPriority, PushType};
use construct_config::{ApnsConfig, ApnsEnvironment};

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

    /// Send push notification to device
    pub async fn send_notification(
        &self,
        device_token: &str,
        payload: ApnsPayload,
        push_type: PushType,
        priority: NotificationPriority,
    ) -> Result<()> {
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
        use crate::apns::DeviceTokenEncryption;
        let token_hash_bytes = DeviceTokenEncryption::hash_token(device_token);
        let token_hash_hex = hex::encode(&token_hash_bytes);
        debug!(
            "Sending APNs notification: device_token_hash={}, push_type={:?}, priority={:?}",
            &token_hash_hex[..8],
            push_type,
            priority
        );
        debug!("APNs payload: {}", payload_json);

        // Create notification options
        let mut options = NotificationOptions {
            apns_topic: Some(&self.config.topic),
            ..Default::default()
        };

        // Set priority if high
        if matches!(priority, NotificationPriority::High) {
            options.apns_priority = Some(Priority::High);
        }

        // Build notification
        let builder = DefaultNotificationBuilder::new()
            .title("New Message")
            .body("You have a new message")
            .build(device_token, options);

        // Send notification
        match client.send(builder).await {
            Ok(_response) => {
                debug!("APNs notification sent successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to send APNs notification: {:?}", e);

                // Check if error indicates invalid token
                // Note: apns-h2 error handling - check ErrorReason for BadDeviceToken
                warn!("APNs error (may indicate invalid token): {}", e);
                // TODO: Parse error response and handle invalid tokens
                // TODO: Check if e contains ErrorReason::BadDeviceToken

                Err(e.into())
            }
        }
    }

    /// Send silent push notification (Phase 1)
    pub async fn send_silent_push(
        &self,
        device_token: &str,
        conversation_id: Option<String>,
    ) -> Result<()> {
        let payload = ApnsPayload::silent(conversation_id);
        self.send_notification(
            device_token,
            payload,
            PushType::Silent,
            NotificationPriority::Low,
        )
        .await
    }

    /// Send visible push notification (Phase 2)
    pub async fn send_visible_push(
        &self,
        device_token: &str,
        sender_name: &str,
        conversation_id: Option<String>,
    ) -> Result<()> {
        let payload = ApnsPayload::visible(sender_name, conversation_id);
        self.send_notification(
            device_token,
            payload,
            PushType::Visible,
            NotificationPriority::High,
        )
        .await
    }

    /// Check if APNs is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}
