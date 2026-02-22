// ============================================================================
// NotificationService Core Business Logic
// ============================================================================
//
// Pure business logic for notification operations, independent of transport layer.
//
// ============================================================================

use anyhow::{Context, Result};
use construct_server_shared::{AppError, apns::DeviceTokenEncryption, utils::log_safe_id};
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

    // Fetch all active device tokens for this user
    let device_tokens = sqlx::query!(
        r#"
        SELECT device_token_encrypted, notification_filter, enabled
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

        // For blind notifications, we respect the filter but don't show content
        let should_send = match (filter, input.activity_type.as_deref()) {
            ("silent", _) => true, // Silent notifications always allowed
            ("visible_all", _) => true,
            ("visible_dm", Some("new_message")) => true,
            ("visible_mentions", Some("mention")) => true,
            ("visible_contacts", Some("new_message" | "mention")) => true,
            _ => false,
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

        // Send blind notification via APNs
        // Note: FCM support can be added here with similar logic
        use construct_server_shared::apns::types::{
            ApnsPayload, ApsData, ConstructData, NotificationPriority, PushType,
        };

        // Create blind notification payload with badge
        let payload = ApnsPayload {
            aps: ApsData {
                content_available: Some(1),
                alert: None,
                sound: None,
                badge: input.badge_count.map(|b| b as u32),
            },
            construct: input.activity_type.as_ref().map(|activity| ConstructData {
                notification_type: activity.clone(),
                conversation_id: None,
            }),
        };

        if let Err(e) = context
            .apns_client
            .send_notification(
                &device_token,
                payload,
                PushType::Silent,
                NotificationPriority::Low,
            )
            .await
        {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to send APNs notification"
            );
            // Continue trying other tokens even if one fails
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

    // Insert or update device token in database
    sqlx::query!(
        r#"
        INSERT INTO device_tokens (user_id, device_token_hash, device_token_encrypted, device_name_encrypted, notification_filter, enabled)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        ON CONFLICT (user_id, device_token_hash)
        DO UPDATE SET
            device_name_encrypted = EXCLUDED.device_name_encrypted,
            notification_filter = EXCLUDED.notification_filter,
            enabled = TRUE
        "#,
        input.user_id,
        token_hash,
        token_encrypted,
        name_encrypted.as_deref(),
        filter
    )
    .execute(&*context.db_pool)
    .await
    .context("Failed to insert/update device token")?;

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
