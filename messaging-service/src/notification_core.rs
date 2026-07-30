use anyhow::{Context, Result};
use construct_config::{ApnsEnvironment, ApnsEnvironments};
use construct_server_shared::{
    AppError,
    apns::{ApnsSendError, DeviceTokenEncryption},
    notification_service::NotificationServiceContext,
    utils::log_safe_id,
};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SendBlindNotificationInput {
    pub user_id: Uuid,
    pub badge_count: Option<i32>,
    pub activity_type: Option<String>,
    pub conversation_id: Option<String>,
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
    pub notification_filter: i32,
    pub device_id: Option<String>,
    pub push_provider: String,
    pub push_environment: String,
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
    pub notification_filter: i32,
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
    pub platform: String,
    pub push_environment: String,
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
pub struct SendKeyRotationWakeInput {
    pub user_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct SendKeyRotationWakeOutput {
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

fn notification_filter_to_string(filter: i32) -> String {
    match filter {
        0 => "silent".to_string(),
        1 => "silent".to_string(),
        2 => "visible_all".to_string(),
        3 => "visible_dm".to_string(),
        4 => "visible_mentions".to_string(),
        5 => "visible_contacts".to_string(),
        _ => "silent".to_string(),
    }
}

fn is_valid_filter(filter: &str) -> bool {
    matches!(
        filter,
        "silent" | "visible_all" | "visible_dm" | "visible_mentions" | "visible_contacts"
    )
}

fn is_valid_platform(platform: &str) -> bool {
    matches!(platform, "ios" | "macos")
}

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

    let mut sent_count = 0;
    for token_row in &device_tokens {
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

        let filter = token_row.notification_filter.as_str();
        let should_send = matches!(
            filter,
            "silent" | "visible_all" | "visible_dm" | "visible_mentions" | "visible_contacts"
        );

        if !should_send {
            tracing::debug!(
                user_hash = %user_id_hash,
                filter = %filter,
                activity_type = ?input.activity_type,
                "Skipping notification due to filter"
            );
            continue;
        }

        if token_row.push_provider != "apns" {
            tracing::debug!(
                user_hash = %user_id_hash,
                push_provider = %token_row.push_provider,
                "Skipping non-APNS token (FCM not yet implemented)"
            );
            continue;
        }
        let environments = ApnsEnvironments::parse_or_both(&token_row.push_environment);

        use construct_server_shared::apns::types::{
            ApnsPayload, ApsData, ConstructData, NotificationPriority, PushType,
        };

        let payload = ApnsPayload {
            aps: ApsData {
                content_available: Some(1u8),
                alert: None,
                sound: None,
                badge: input.badge_count.map(|b| b as u32),
            },
            construct: input.activity_type.as_ref().map(|activity| ConstructData {
                notification_type: activity.clone(),
                conversation_id: input.conversation_id.clone(),
            }),
            construct_call: None,
        };
        let push_type = PushType::Silent;
        let priority = NotificationPriority::Low;

        const MAX_ATTEMPTS: u32 = 3;
        let mut succeeded_on: Option<ApnsEnvironment> = None;
        // Only condemn the token once EVERY declared environment has rejected it. A row
        // that says "sandbox,production" is telling us the environment is unknown, so a
        // rejection from one endpoint proves nothing about the token itself.
        let mut rejected_by_all = true;
        'env: for environment in environments.iter() {
            let apns_client = match environment {
                ApnsEnvironment::Development => &context.apns_sandbox_client,
                ApnsEnvironment::Production => &context.apns_client,
            };
            for attempt in 1..=MAX_ATTEMPTS {
                match apns_client
                    .send_notification(&device_token, payload.clone(), push_type, priority)
                    .await
                {
                    Ok(()) => {
                        succeeded_on = Some(environment);
                        rejected_by_all = false;
                        break 'env;
                    }
                    Err(ApnsSendError::InvalidToken) => {
                        tracing::debug!(
                            user_hash = %user_id_hash,
                            environment = %environment.as_str(),
                            remaining = environments.len() - 1,
                            "APNs rejected the token on this endpoint"
                        );
                        continue 'env;
                    }
                    Err(ref e) if attempt < MAX_ATTEMPTS => {
                        let delay = Duration::from_millis(100 * 3_u64.pow(attempt - 1));
                        tracing::warn!(
                            error = %e,
                            user_hash = %user_id_hash,
                            environment = %environment.as_str(),
                            attempt = attempt,
                            retry_ms = delay.as_millis(),
                            "APNs send failed — retrying"
                        );
                        tokio::time::sleep(delay).await;
                    }
                    Err(e) => {
                        // A transport/auth failure is NOT a verdict on the token — do not
                        // let it count towards deletion.
                        tracing::error!(
                            error = %e,
                            user_hash = %user_id_hash,
                            environment = %environment.as_str(),
                            "APNs send failed after all retries — giving up on this endpoint"
                        );
                        rejected_by_all = false;
                        continue 'env;
                    }
                }
            }
        }
        if rejected_by_all {
            tracing::warn!(
                user_hash = %user_id_hash,
                push_environment = %token_row.push_environment,
                push_provider = %token_row.push_provider,
                "APNs: token rejected by every declared environment — deleting from DB"
            );
            if let Err(db_err) =
                sqlx::query("DELETE FROM device_tokens WHERE device_token_encrypted = $1")
                    .bind(&token_row.device_token_encrypted)
                    .execute(&*context.db_pool)
                    .await
            {
                tracing::error!(
                    error = %db_err,
                    user_hash = %user_id_hash,
                    "Failed to delete invalid device token from DB"
                );
            }
            continue;
        }
        let Some(environment) = succeeded_on else {
            continue;
        };

        // Narrow an unknown-environment row to the endpoint that actually worked, so the
        // probe is paid once per token rather than once per push.
        if environments.len() > 1 {
            let resolved = environment.as_str();
            if let Err(db_err) = sqlx::query(
                "UPDATE device_tokens SET push_environment = $1 WHERE device_token_encrypted = $2",
            )
            .bind(resolved)
            .bind(&token_row.device_token_encrypted)
            .execute(&*context.db_pool)
            .await
            {
                // Non-fatal: the push was delivered, we just probe again next time.
                tracing::warn!(
                    error = %db_err,
                    user_hash = %user_id_hash,
                    "Failed to pin resolved APNs environment"
                );
            } else {
                tracing::info!(
                    user_hash = %user_id_hash,
                    environment = %resolved,
                    "Resolved APNs environment for token"
                );
            }
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

    // 512: APNs tokens are 64 hex chars, but FCM registration tokens routinely exceed 128
    // and Google documents no upper bound — a tight cap silently locks Android clients out.
    if input.device_token.is_empty() || input.device_token.len() > 512 {
        tracing::warn!(
            user_hash = %user_id_hash,
            token_len = input.device_token.len(),
            "Invalid device token format"
        );
        return Err(AppError::Validation("Device token format is invalid".to_string()).into());
    }

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

/// Send a silent background push for key rotation/replenishment
pub async fn send_key_rotation_wake(
    context: &NotificationServiceContext,
    input: SendKeyRotationWakeInput,
) -> Result<SendKeyRotationWakeOutput> {
    let user_id_hash = log_safe_id(
        &input.user_id.to_string(),
        &context.config.logging.hash_salt,
    );

    tracing::info!(user_hash = %user_id_hash, "Sending key rotation wake push");

    let rows = sqlx::query(
        r#"
        SELECT device_token_encrypted, push_provider, push_environment
        FROM device_tokens
        WHERE user_id = $1 AND enabled = TRUE
        "#,
    )
    .bind(input.user_id)
    .fetch_all(&*context.db_pool)
    .await
    .context("Failed to fetch device tokens")?;

    struct TokenRow {
        device_token_encrypted: Vec<u8>,
        push_provider: String,
        push_environment: String,
    }

    let device_tokens: Vec<TokenRow> = rows
        .into_iter()
        .map(|row| {
            Ok(TokenRow {
                device_token_encrypted: row.try_get("device_token_encrypted")?,
                push_provider: row.try_get("push_provider")?,
                push_environment: row.try_get("push_environment")?,
            })
        })
        .collect::<Result<Vec<_>>>()
        .context("Failed to parse device token rows")?;

    if device_tokens.is_empty() {
        tracing::debug!(user_hash = %user_id_hash, "No active device tokens for key rotation wake");
        return Ok(SendKeyRotationWakeOutput { success: false });
    }

    use construct_server_shared::apns::types::{ApnsPayload, NotificationPriority, PushType};

    let payload = ApnsPayload::key_rotation_wake();

    let mut sent_any = false;
    for token_row in &device_tokens {
        let device_token = match context
            .token_encryption
            .decrypt(&token_row.device_token_encrypted)
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, user_hash = %user_id_hash, "Failed to decrypt device token");
                continue;
            }
        };

        if token_row.push_provider != "apns" {
            continue;
        }
        let environments = ApnsEnvironments::parse_or_both(&token_row.push_environment);

        let mut rejected_by_all = true;
        for environment in environments.iter() {
            let apns_client = match environment {
                ApnsEnvironment::Development => &context.apns_sandbox_client,
                ApnsEnvironment::Production => &context.apns_client,
            };

            match apns_client
                .send_notification(
                    &device_token,
                    payload.clone(),
                    PushType::Silent,
                    NotificationPriority::Low,
                )
                .await
            {
                Ok(()) => {
                    sent_any = true;
                    rejected_by_all = false;
                    break;
                }
                Err(ApnsSendError::InvalidToken) => {
                    tracing::debug!(
                        user_hash = %user_id_hash,
                        environment = %environment.as_str(),
                        "APNs rejected the token on this endpoint (key-rotation wake)"
                    );
                }
                Err(ApnsSendError::Other(e)) => {
                    // Not a verdict on the token — never let it lead to deletion.
                    tracing::warn!(error = %e, user_hash = %user_id_hash, environment = %environment.as_str(), "APNs send failed (best-effort)");
                    rejected_by_all = false;
                }
            }
        }

        if rejected_by_all {
            tracing::warn!(user_hash = %user_id_hash, push_environment = %token_row.push_environment, "APNs token rejected by every declared environment — deleting");
            if let Err(db_err) =
                sqlx::query("DELETE FROM device_tokens WHERE device_token_encrypted = $1")
                    .bind(&token_row.device_token_encrypted)
                    .execute(&*context.db_pool)
                    .await
            {
                tracing::error!(
                    error = %db_err,
                    user_hash = %user_id_hash,
                    "Failed to delete invalid device token after key-rotation wake"
                );
            }
        }
    }

    tracing::info!(user_hash = %user_id_hash, sent_any, "Key rotation wake processed");
    Ok(SendKeyRotationWakeOutput { success: sent_any })
}

/// Per-recipient VoIP push budget (defense in depth; signaling also rate-limits calls).
const VOIP_PUSH_MAX_PER_WINDOW: i64 = 10;
const VOIP_PUSH_WINDOW_SECS: i64 = 60;
/// Per (caller → recipient) pair budget within the same window.
const VOIP_PUSH_PEER_MAX_PER_WINDOW: i64 = 3;

/// Send a VoIP push notification for an incoming call.
///
/// SECURITY: the push payload is server-constructed and visible to Apple/APNs.
/// It only wakes the device / CallKit. The actual call authorization (caller
/// identity, DTLS fingerprint, etc.) happens inside the E2EE signaling path.
///
/// Rate limits (Redis): recipient total + caller→recipient pair, aligned with
/// signaling call limits. Redis errors fail-open + metric so push availability
/// is not lost during an outage.
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

    // VoIP push rate limits (recipient + peer pair).
    {
        let mut queue = context.queue.lock().await;
        let recip_key = format!("rate:voip:{}", input.user_id);
        match queue
            .increment_rate_limit(&recip_key, VOIP_PUSH_WINDOW_SECS)
            .await
        {
            Ok(count) if count > VOIP_PUSH_MAX_PER_WINDOW => {
                tracing::warn!(
                    user_hash = %user_id_hash,
                    count,
                    limit = VOIP_PUSH_MAX_PER_WINDOW,
                    "VoIP push rate limit exceeded (recipient)"
                );
                return Err(
                    AppError::TooManyRequests("VoIP push rate limit exceeded".to_string()).into(),
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_hash = %user_id_hash,
                    "VoIP recipient rate limit Redis error; failing open"
                );
                construct_metrics::record_abuse_fail_open("voip_push");
            }
        }

        let peer_key = format!("rate:voip:{}:{}", input.caller_id, input.user_id);
        match queue
            .increment_rate_limit(&peer_key, VOIP_PUSH_WINDOW_SECS)
            .await
        {
            Ok(count) if count > VOIP_PUSH_PEER_MAX_PER_WINDOW => {
                tracing::warn!(
                    user_hash = %user_id_hash,
                    count,
                    limit = VOIP_PUSH_PEER_MAX_PER_WINDOW,
                    "VoIP push peer rate limit exceeded"
                );
                return Err(AppError::TooManyRequests(
                    "VoIP push peer rate limit exceeded".to_string(),
                )
                .into());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_hash = %user_id_hash,
                    "VoIP peer rate limit Redis error; failing open"
                );
                construct_metrics::record_abuse_fail_open("voip_push");
            }
        }
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
                if let Err(db_err) =
                    sqlx::query("UPDATE voip_tokens SET enabled = FALSE WHERE id = $1")
                        .bind(token_id)
                        .execute(&*context.db_pool)
                        .await
                {
                    tracing::error!(
                        error = %db_err,
                        user_hash = %user_id_hash,
                        "Failed to disable VoIP token after decrypt failure"
                    );
                }
                continue;
            }
        };

        let environments = ApnsEnvironments::parse_or_both(&push_environment);

        let mut delivered_on: Option<ApnsEnvironment> = None;
        let mut rejected_by_all = true;
        for environment in environments.iter() {
            let apns_client = match environment {
                ApnsEnvironment::Development => &context.apns_sandbox_client,
                ApnsEnvironment::Production => &context.apns_client,
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
                    delivered_on = Some(environment);
                    rejected_by_all = false;
                    break;
                }
                Err(ApnsSendError::InvalidToken) => {
                    tracing::debug!(
                        user_hash = %user_id_hash,
                        environment = %environment.as_str(),
                        "VoIP token rejected on this endpoint"
                    );
                }
                Err(ApnsSendError::Other(e)) => {
                    // Transport/auth failure — says nothing about the token.
                    tracing::warn!(
                        error = %e,
                        user_hash = %user_id_hash,
                        environment = %environment.as_str(),
                        "Failed to send VoIP push (best-effort)"
                    );
                    rejected_by_all = false;
                }
            }
        }

        if rejected_by_all {
            tracing::info!(
                user_hash = %user_id_hash,
                push_environment = %push_environment,
                "VoIP token rejected by every declared environment - disabling"
            );
            if let Err(db_err) = sqlx::query("UPDATE voip_tokens SET enabled = FALSE WHERE id = $1")
                .bind(token_id)
                .execute(&*context.db_pool)
                .await
            {
                tracing::error!(
                    error = %db_err,
                    user_hash = %user_id_hash,
                    "Failed to disable VoIP token after APNs InvalidToken"
                );
            }
        } else if let Some(environment) = delivered_on {
            if environments.len() > 1 {
                if let Err(db_err) =
                    sqlx::query("UPDATE voip_tokens SET push_environment = $1 WHERE id = $2")
                        .bind(environment.as_str())
                        .bind(token_id)
                        .execute(&*context.db_pool)
                        .await
                {
                    tracing::warn!(
                        error = %db_err,
                        user_hash = %user_id_hash,
                        "Failed to pin resolved APNs environment for VoIP token"
                    );
                }
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
