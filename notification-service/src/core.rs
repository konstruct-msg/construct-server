// ============================================================================
// NotificationService Core Business Logic
// ============================================================================
//
// Pure business logic for notification operations, independent of transport layer.
//
// ============================================================================

use anyhow::{Context, Result};
use construct_server_shared::{
    AppError,
    apns::{ApnsSendError, DeviceTokenEncryption},
    utils::log_safe_id,
};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

use crate::NotificationServiceContext;

// ============================================================================
// Core Business Logic Structs
// ============================================================================

#[derive(Debug, Clone)]
pub struct SendBlindNotificationInput {
    pub user_id: Uuid,
    pub badge_count: Option<i32>,
    pub activity_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SendBlindNotificationOutput {
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterDeviceTokenInput {
    pub user_id: Uuid,
    pub device_token: String,
    pub device_name: Option<String>,
    pub notification_filter: i32, // proto enum as i32
    pub device_id: Option<String>,
    pub push_provider: String,    // "apns" | "fcm"
    pub push_environment: String, // "sandbox" | "production"
}

#[derive(Debug, Clone)]
pub struct RegisterDeviceTokenOutput {
    pub success: bool,
    pub token_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UnregisterDeviceTokenInput {
    pub user_id: Uuid,
    pub device_token: String,
}

#[derive(Debug, Clone)]
pub struct UnregisterDeviceTokenOutput {
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateNotificationPreferencesInput {
    pub user_id: Uuid,
    pub device_token: String,
    pub notification_filter: i32, // proto enum as i32
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateNotificationPreferencesOutput {
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterVoipTokenInput {
    pub user_id: Uuid,
    pub voip_token: String,
    pub device_id: String,
    pub platform: String,         // "ios" | "macos"
    pub push_environment: String, // "sandbox" | "production"
}

#[derive(Debug, Clone)]
pub struct RegisterVoipTokenOutput {
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct UnregisterVoipTokenInput {
    pub user_id: Uuid,
    pub device_id: String,
}

#[derive(Debug, Clone)]
pub struct UnregisterVoipTokenOutput {
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct SendVoipIncomingCallInput {
    pub user_id: Uuid,
    pub call_id: String,
    pub caller_id: String,
    pub caller_name: String,
    pub call_type: String,
    pub offered_at: i64,
}

#[derive(Debug, Clone)]
pub struct SendVoipIncomingCallOutput {
    pub success: bool,
    pub sent_count: i32,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert proto NotificationFilter enum to string
fn notification_filter_to_string(filter: i32) -> String {
    match filter {
        0 => "silent".to_string(),           // NOTIFICATION_FILTER_UNSPECIFIED
        1 => "silent".to_string(),           // NOTIFICATION_FILTER_SILENT
        2 => "visible_all".to_string(),      // NOTIFICATION_FILTER_VISIBLE_ALL
        3 => "visible_dm".to_string(),       // NOTIFICATION_FILTER_VISIBLE_DM
        4 => "visible_mentions".to_string(), // NOTIFICATION_FILTER_VISIBLE_MENTIONS
        5 => "visible_contacts".to_string(), // NOTIFICATION_FILTER_VISIBLE_CONTACTS
        _ => "silent".to_string(),           // Unknown -> default to silent
    }
}

/// Validate notification filter string
fn is_valid_filter(filter: &str) -> bool {
    matches!(
        filter,
        "silent" | "visible_all" | "visible_dm" | "visible_mentions" | "visible_contacts"
    )
}

fn is_valid_platform(platform: &str) -> bool {
    matches!(platform, "ios" | "macos")
}

// ============================================================================
// Core Business Logic Functions
// ============================================================================

/// Send blind notification (privacy-preserving push)
pub async fn send_blind_notification(
    context: &NotificationServiceContext,
    input: SendBlindNotificationInput,
) -> Result<SendBlindNotificationOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    tracing::info!(
        user_hash = %user_id_hash,
        badge_count = ?input.badge_count,
        activity_type = ?input.activity_type,
        "Sending blind notification"
    );

    // Fetch all active device tokens for this user (including environment for APNS routing)
    let device_tokens = sqlx::query!(
        r#"
        SELECT device_token_encrypted, notification_filter, enabled,
               push_provider, push_environment
        FROM device_tokens
        WHERE user_id = $1 AND enabled = TRUE
        "#,
        input.user_id
    )
    .fetch_all(&*context.db_pool)
    .await
    .context("Failed to fetch device tokens")?;

    if device_tokens.is_empty() {
        tracing::debug!(
            user_hash = %user_id_hash,
            "No active device tokens found for user"
        );
        return Ok(SendBlindNotificationOutput { success: true });
    }

    // Decrypt and send notifications
    let mut sent_count = 0;
    for token_row in &device_tokens {
        // Decrypt device token
        let device_token = context
            .token_encryption
            .decrypt(&token_row.device_token_encrypted)
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    user_hash = %user_id_hash,
                    "Failed to decrypt device token"
                );
                e
            })?;

        // Check notification filter - only send if user allows it
        let filter = token_row.notification_filter.as_str();

        // Determine push type based on user's filter preference:
        // - "silent" → background wake-up only (content-available: 1, no alert)
        // - any "visible_*" that matches activity → show visible alert notification
        let (should_send, use_visible) = match (filter, input.activity_type.as_deref()) {
            ("silent", _) => (true, false),
            ("visible_all", _) => (true, true),
            ("visible_dm", Some("new_message")) => (true, true),
            ("visible_mentions", Some("mention")) => (true, true),
            ("visible_contacts", Some("new_message" | "mention")) => (true, true),
            _ => (false, false),
        };

        if !should_send {
            tracing::debug!(
                user_hash = %user_id_hash,
                filter = %filter,
                activity_type = ?input.activity_type,
                "Skipping notification due to filter"
            );
            continue;
        }

        // Route to the correct APNS client based on the token's push_environment.
        // The same .p8 key is valid for both endpoints, but sending a sandbox token
        // to the production endpoint (or vice versa) silently fails with BadDeviceToken.
        let apns_client = if token_row.push_provider == "apns" {
            match token_row.push_environment.as_str() {
                "sandbox" => &context.apns_sandbox_client,
                _ => &context.apns_client,
            }
        } else {
            // FCM and other providers not yet implemented — skip silently
            tracing::debug!(
                user_hash = %user_id_hash,
                push_provider = %token_row.push_provider,
                "Skipping non-APNS token (FCM not yet implemented)"
            );
            continue;
        };

        // Send notification via APNs
        // Note: FCM support can be added here with similar logic
        use construct_server_shared::apns::types::{
            AlertData, ApnsPayload, ApsData, ConstructData, NotificationPriority, PushType,
        };

        let (push_type, priority, content_available, alert) = if use_visible {
            // Visible alert: high priority, alert text + content-available to wake app in background
            (
                PushType::Visible,
                NotificationPriority::High,
                Some(1u8),
                Some(AlertData {
                    title: "Construct".to_string(),
                    body: "New message".to_string(),
                }),
            )
        } else {
            // Silent background push: low priority, content-available = 1, no alert
            (PushType::Silent, NotificationPriority::Low, Some(1u8), None)
        };

        let payload = ApnsPayload {
            aps: ApsData {
                content_available,
                alert,
                sound: if use_visible {
                    Some("default".to_string())
                } else {
                    None
                },
                badge: input.badge_count.map(|b| b as u32),
            },
            construct: input.activity_type.as_ref().map(|activity| ConstructData {
                notification_type: activity.clone(),
                conversation_id: None,
            }),
            construct_call: None,
        };

        // Retry with exponential backoff: 100ms → 300ms → 900ms (3 attempts total).
        // Skip retrying immediately on InvalidToken — APNs won't accept it regardless.
        const MAX_ATTEMPTS: u32 = 3;
        let mut succeeded = false;
        let mut invalid_token = false;
        for attempt in 1..=MAX_ATTEMPTS {
            match apns_client
                .send_notification(&device_token, payload.clone(), push_type, priority)
                .await
            {
                Ok(()) => {
                    succeeded = true;
                    break;
                }
                Err(ApnsSendError::InvalidToken) => {
                    invalid_token = true;
                    break; // no retries — token is permanently dead
                }
                Err(ref e) if attempt < MAX_ATTEMPTS => {
                    let delay = Duration::from_millis(100 * 3_u64.pow(attempt - 1));
                    tracing::warn!(
                        error = %e,
                        user_hash = %user_id_hash,
                        attempt = attempt,
                        retry_ms = delay.as_millis(),
                        "APNs send failed — retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user_hash = %user_id_hash,
                        "APNs send failed after all retries — giving up on this token"
                    );
                }
            }
        }
        if invalid_token {
            tracing::warn!(
                user_hash = %user_id_hash,
                push_environment = %token_row.push_environment,
                push_provider = %token_row.push_provider,
                "APNs: token invalid/rejected (BadDeviceToken, Unregistered, or 403 Forbidden — possible sandbox/production mismatch) — deleting from DB"
            );
            let _ = sqlx::query("DELETE FROM device_tokens WHERE device_token_encrypted = $1")
                .bind(&token_row.device_token_encrypted)
                .execute(&*context.db_pool)
                .await
                .map_err(|db_err| {
                    tracing::error!(
                        error = %db_err,
                        "Failed to delete invalid device token from DB"
                    );
                });
            continue;
        }
        if !succeeded {
            continue;
        }

        sent_count += 1;
    }

    tracing::info!(
        user_hash = %user_id_hash,
        sent_count = sent_count,
        total_tokens = device_tokens.len(),
        "Blind notifications sent"
    );

    Ok(SendBlindNotificationOutput { success: true })
}

/// Register device token for push notifications
pub async fn register_device_token(
    context: &NotificationServiceContext,
    input: RegisterDeviceTokenInput,
) -> Result<RegisterDeviceTokenOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    // Validate device token format
    if input.device_token.is_empty() || input.device_token.len() > 128 {
        tracing::warn!(
            user_hash = %user_id_hash,
            "Invalid device token format"
        );
        return Err(AppError::Validation("Device token format is invalid".to_string()).into());
    }

    // Convert proto filter to string
    let filter = notification_filter_to_string(input.notification_filter);

    if !is_valid_filter(&filter) {
        tracing::warn!(
            user_hash = %user_id_hash,
            filter = %filter,
            "Invalid notification filter"
        );
        return Err(
            AppError::Validation(format!("Invalid notification filter: {}", filter)).into(),
        );
    }

    tracing::debug!(
        user_hash = %user_id_hash,
        filter = %filter,
        "Registering device token"
    );

    // Encrypt device token and device name
    let token_hash = DeviceTokenEncryption::hash_token(&input.device_token);
    let token_encrypted = context
        .token_encryption
        .encrypt(&input.device_token)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to encrypt device token"
            );
            e
        })?;

    let name_encrypted = if let Some(ref name) = input.device_name {
        Some(context.token_encryption.encrypt(name).map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to encrypt device name"
            );
            e
        })?)
    } else {
        None
    };

    // Insert or update device token in database.
    // Conflict resolution:
    //   - If device_id provided: upsert on (user_id, device_id) — handles token rotation
    //   - Otherwise: upsert on (user_id, device_token_hash) — legacy path
    if let Some(ref device_id) = input.device_id {
        sqlx::query(
            r#"
            INSERT INTO device_tokens
                (user_id, device_token_hash, device_token_encrypted, device_name_encrypted,
                 notification_filter, enabled, device_id, push_provider, push_environment)
            VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7, $8)
            ON CONFLICT (user_id, device_id) WHERE device_id IS NOT NULL
            DO UPDATE SET
                device_token_hash      = EXCLUDED.device_token_hash,
                device_token_encrypted = EXCLUDED.device_token_encrypted,
                device_name_encrypted  = EXCLUDED.device_name_encrypted,
                notification_filter    = EXCLUDED.notification_filter,
                push_provider          = EXCLUDED.push_provider,
                push_environment       = EXCLUDED.push_environment,
                enabled                = TRUE
            "#,
        )
        .bind(input.user_id)
        .bind(&token_hash)
        .bind(&token_encrypted)
        .bind(name_encrypted.as_deref())
        .bind(&filter)
        .bind(device_id)
        .bind(&input.push_provider)
        .bind(&input.push_environment)
        .execute(&*context.db_pool)
        .await
        .context("Failed to insert/update device token")?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO device_tokens
                (user_id, device_token_hash, device_token_encrypted, device_name_encrypted,
                 notification_filter, enabled, push_provider, push_environment)
            VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
            ON CONFLICT (user_id, device_token_hash)
            DO UPDATE SET
                device_name_encrypted = EXCLUDED.device_name_encrypted,
                notification_filter   = EXCLUDED.notification_filter,
                push_provider         = EXCLUDED.push_provider,
                push_environment      = EXCLUDED.push_environment,
                enabled               = TRUE
            "#,
        )
        .bind(input.user_id)
        .bind(&token_hash)
        .bind(&token_encrypted)
        .bind(name_encrypted.as_deref())
        .bind(&filter)
        .bind(&input.push_provider)
        .bind(&input.push_environment)
        .execute(&*context.db_pool)
        .await
        .context("Failed to insert/update device token")?;
    }

    tracing::info!(
        user_hash = %user_id_hash,
        filter = %filter,
        "Device token registered successfully"
    );

    Ok(RegisterDeviceTokenOutput {
        success: true,
        token_id: Some(hex::encode(token_hash)),
    })
}

/// Unregister device token
pub async fn unregister_device_token(
    context: &NotificationServiceContext,
    input: UnregisterDeviceTokenInput,
) -> Result<UnregisterDeviceTokenOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    let token_hash = DeviceTokenEncryption::hash_token(&input.device_token);

    // Delete device token from database
    let result = sqlx::query!(
        r#"
        DELETE FROM device_tokens
        WHERE user_id = $1 AND device_token_hash = $2
        "#,
        input.user_id,
        token_hash
    )
    .execute(&*context.db_pool)
    .await
    .context("Failed to delete device token")?;

    let success = result.rows_affected() > 0;

    if success {
        tracing::info!(
            user_hash = %user_id_hash,
            "Device token unregistered successfully"
        );
    } else {
        tracing::warn!(
            user_hash = %user_id_hash,
            "Device token not found for unregistration"
        );
    }

    Ok(UnregisterDeviceTokenOutput { success })
}

/// Update notification preferences
pub async fn update_notification_preferences(
    context: &NotificationServiceContext,
    input: UpdateNotificationPreferencesInput,
) -> Result<UpdateNotificationPreferencesOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    let token_hash = DeviceTokenEncryption::hash_token(&input.device_token);
    let filter = notification_filter_to_string(input.notification_filter);

    if !is_valid_filter(&filter) {
        tracing::warn!(
            user_hash = %user_id_hash,
            filter = %filter,
            "Invalid notification filter"
        );
        return Err(
            AppError::Validation(format!("Invalid notification filter: {}", filter)).into(),
        );
    }

    // Update preferences in database
    let result = sqlx::query!(
        r#"
        UPDATE device_tokens
        SET notification_filter = $1, enabled = $2
        WHERE user_id = $3 AND device_token_hash = $4
        "#,
        filter,
        input.enabled,
        input.user_id,
        token_hash
    )
    .execute(&*context.db_pool)
    .await
    .context("Failed to update notification preferences")?;

    let success = result.rows_affected() > 0;

    if success {
        tracing::info!(
            user_hash = %user_id_hash,
            filter = %filter,
            enabled = input.enabled,
            "Notification preferences updated successfully"
        );
    } else {
        tracing::warn!(
            user_hash = %user_id_hash,
            "Device token not found for preference update"
        );
    }

    Ok(UpdateNotificationPreferencesOutput { success })
}

/// Register VoIP token (APNs VoIP)
pub async fn register_voip_token(
    context: &NotificationServiceContext,
    input: RegisterVoipTokenInput,
) -> Result<RegisterVoipTokenOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    if input.voip_token.is_empty() || input.voip_token.len() > 256 {
        tracing::warn!(user_hash = %user_id_hash, "Invalid VoIP token format");
        return Err(AppError::Validation("VoIP token format is invalid".to_string()).into());
    }
    if input.device_id.is_empty() || input.device_id.len() > 128 {
        tracing::warn!(user_hash = %user_id_hash, "Invalid device_id format");
        return Err(AppError::Validation("device_id format is invalid".to_string()).into());
    }
    if !is_valid_platform(&input.platform) {
        tracing::warn!(user_hash = %user_id_hash, platform = %input.platform, "Invalid platform");
        return Err(AppError::Validation("platform is invalid".to_string()).into());
    }

    let token_hash = DeviceTokenEncryption::hash_token(&input.voip_token);
    let token_encrypted = context
        .token_encryption
        .encrypt(&input.voip_token)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to encrypt VoIP token"
            );
            e
        })?;

    sqlx::query(
        r#"
        INSERT INTO voip_tokens
            (user_id, device_id, voip_token_hash, voip_token_encrypted,
             platform, push_environment, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, TRUE)
        ON CONFLICT (user_id, device_id)
        DO UPDATE SET
            voip_token_hash      = EXCLUDED.voip_token_hash,
            voip_token_encrypted = EXCLUDED.voip_token_encrypted,
            platform             = EXCLUDED.platform,
            push_environment     = EXCLUDED.push_environment,
            enabled              = TRUE
        "#,
    )
    .bind(input.user_id)
    .bind(&input.device_id)
    .bind(&token_hash)
    .bind(&token_encrypted)
    .bind(&input.platform)
    .bind(&input.push_environment)
    .execute(&*context.db_pool)
    .await
    .context("Failed to insert/update voip token")?;

    tracing::info!(user_hash = %user_id_hash, "VoIP token registered successfully");
    Ok(RegisterVoipTokenOutput { success: true })
}

/// Unregister VoIP token by device_id
pub async fn unregister_voip_token(
    context: &NotificationServiceContext,
    input: UnregisterVoipTokenInput,
) -> Result<UnregisterVoipTokenOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    if input.device_id.is_empty() || input.device_id.len() > 128 {
        tracing::warn!(user_hash = %user_id_hash, "Invalid device_id format");
        return Err(AppError::Validation("device_id format is invalid".to_string()).into());
    }

    let result = sqlx::query(
        r#"
        DELETE FROM voip_tokens
        WHERE user_id = $1 AND device_id = $2
        "#,
    )
    .bind(input.user_id)
    .bind(&input.device_id)
    .execute(&*context.db_pool)
    .await
    .context("Failed to delete voip token")?;

    let success = result.rows_affected() > 0;

    if success {
        tracing::info!(user_hash = %user_id_hash, "VoIP token unregistered successfully");
    } else {
        tracing::warn!(user_hash = %user_id_hash, "VoIP token not found for unregistration");
    }

    Ok(UnregisterVoipTokenOutput { success })
}

/// Internal: send VoIP push notification for an incoming call.
///
/// Best-effort: sends to all enabled devices for `user_id`, and disables tokens
/// permanently rejected by APNs.
pub async fn send_voip_incoming_call(
    context: &NotificationServiceContext,
    input: SendVoipIncomingCallInput,
) -> Result<SendVoipIncomingCallOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    if input.call_id.is_empty() || input.call_id.len() > 64 {
        return Err(AppError::Validation("call_id format is invalid".to_string()).into());
    }
    if input.caller_id.is_empty() || input.caller_id.len() > 64 {
        return Err(AppError::Validation("caller_id format is invalid".to_string()).into());
    }
    if input.caller_name.len() > 128 {
        return Err(AppError::Validation("caller_name too long".to_string()).into());
    }
    if input.call_type.is_empty() || input.call_type.len() > 16 {
        return Err(AppError::Validation("call_type format is invalid".to_string()).into());
    }

    let rows = sqlx::query(
        r#"
        SELECT id, voip_token_encrypted, push_environment
        FROM voip_tokens
        WHERE user_id = $1 AND enabled = TRUE
        "#,
    )
    .bind(input.user_id)
    .fetch_all(&*context.db_pool)
    .await
    .context("Failed to fetch voip tokens")?;

    if rows.is_empty() {
        tracing::info!(user_hash = %user_id_hash, "No enabled VoIP tokens for user");
        return Ok(SendVoipIncomingCallOutput {
            success: true,
            sent_count: 0,
        });
    }

    let mut sent_count: i32 = 0;

    for row in rows {
        let token_id: Uuid = row.try_get("id").context("Missing voip token id")?;
        let token_encrypted: Vec<u8> = row
            .try_get("voip_token_encrypted")
            .context("Missing voip token encrypted")?;
        let push_environment: String = row
            .try_get("push_environment")
            .context("Missing voip token push_environment")?;

        let token = match context.token_encryption.decrypt(&token_encrypted) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_hash = %user_id_hash,
                    "Failed to decrypt VoIP token - disabling"
                );
                let _ = sqlx::query("UPDATE voip_tokens SET enabled = FALSE WHERE id = $1")
                    .bind(token_id)
                    .execute(&*context.db_pool)
                    .await;
                continue;
            }
        };

        let apns_client = match push_environment.as_str() {
            "sandbox" => &context.apns_sandbox_client,
            _ => &context.apns_client,
        };

        match apns_client
            .send_voip_incoming_call_push(
                &token,
                input.call_id.clone(),
                input.caller_id.clone(),
                input.caller_name.clone(),
                input.call_type.clone(),
                input.offered_at,
            )
            .await
        {
            Ok(()) => {
                sent_count += 1;
            }
            Err(ApnsSendError::InvalidToken) => {
                tracing::info!(
                    user_hash = %user_id_hash,
                    push_environment = %push_environment,
                    "VoIP token rejected by APNs - disabling"
                );
                let _ = sqlx::query("UPDATE voip_tokens SET enabled = FALSE WHERE id = $1")
                    .bind(token_id)
                    .execute(&*context.db_pool)
                    .await;
            }
            Err(ApnsSendError::Other(e)) => {
                tracing::warn!(
                    error = %e,
                    user_hash = %user_id_hash,
                    push_environment = %push_environment,
                    "Failed to send VoIP push (best-effort)"
                );
            }
        }
    }

    tracing::info!(
        user_hash = %user_id_hash,
        sent_count,
        "VoIP incoming call push processed"
    );

    Ok(SendVoipIncomingCallOutput {
        success: true,
        sent_count,
    })
}
