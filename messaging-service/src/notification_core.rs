use anyhow::{Context, Result};
use construct_config::{ApnsEnvironment, ApnsEnvironments};
use construct_server_shared::apns::types::AlertData;
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
    /// Whether the push may show a banner. False for an envelope a user sent to their own
    /// devices (SENDER_SYNC, read markers): it wakes the device to fetch, and says nothing —
    /// writing on the Desktop rang the phone with "New message" for every line (2026-10-19).
    pub announce: bool,
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

/// What to do with a token every declared endpoint has rejected.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RejectionVerdict {
    /// Both real endpoints have now said no. The token is dead.
    Delete,
    /// Only one endpoint was ever tried, because the client named one. `BadDeviceToken` from
    /// a single endpoint does not distinguish a dead token from a live one presented to the
    /// wrong endpoint, so widen the row to both and let the next push find out.
    Widen,
}
/// APNs answers `BadDeviceToken` both for a token that is dead and for a live token sent to the
/// wrong endpoint. When the row named one environment, a rejection is evidence against the
/// *pairing*, and the declaration is the likelier half to be wrong — deleting on it destroys a
/// working token and the client re-registers an identically mislabelled one, so pushes stop for
/// good.
///
/// That loop ran on 2026-08-18. A Beta build installed from Xcode declares `production` in
/// Info.plist and is signed for development, so APNs minted a sandbox token and the client
/// announced production; the row was deleted at 13:52:23, re-registered, deleted again at
/// 14:02:49, and by 14:08 the user had no token at all. The client half is fixed in
/// `PushEnvironmentResolver`; this is the half that does not need an app update to stop the
/// bleeding, and that keeps holding when some future build gets its declaration wrong again.
///
/// Cost of being wrong in this direction: a genuinely dead token survives one extra push cycle.
pub(crate) fn verdict_after_rejection(declared_environments: usize) -> RejectionVerdict {
    if declared_environments > 1 {
        RejectionVerdict::Delete
    } else {
        RejectionVerdict::Widen
    }
}

/// The banner a push carries, if any: none for a device that asked for silent pushes, none for
/// an envelope its sender sent to their own devices (`announce == false`), else the activity's.
fn push_alert(filter: &str, announce: bool, activity_type: Option<&str>) -> Option<AlertData> {
    if filter == "silent" || !announce {
        None
    } else {
        blind_alert(activity_type)
    }
}

/// The banner a blind push carries, if its activity is one a person should see.
///
/// Until 2026-10-05 every blind push was a background push (`content-available`, priority 5)
/// and the banner was the app's own, posted after iOS woke it to fetch. iOS wakes an app for
/// such a push at its discretion: throttled, deferred in Low Power Mode, never after the app
/// was swiped away. On TestFlight builds that meant no banner at all, while APNs accepted
/// every push. A banner the system shows itself does not depend on the wake.
///
/// The alert names keys, not text: the device writes "New message" in the reader's language,
/// and the server learns nothing it did not already — the push's time and recipient. The same
/// generic text the app's own banner used, so the lock screen says nothing more than before.
/// Key-maintenance wakes and everything else stay background pushes.
fn blind_alert(activity_type: Option<&str>) -> Option<AlertData> {
    let loc_key = match activity_type? {
        "new_message" => "construct_new_message",
        "contact_request_received" => "contact_request_received_body",
        _ => return None,
    };
    Some(AlertData::Localized {
        title_loc_key: "construct_app_name",
        loc_key,
    })
}

/// Whether the alert goes to the app's notification service extension first
/// (`mutable-content: 1`): only a message's alert. The extension decrypts what the push
/// announces on the device and drops the alert when it is a protocol frame (a delivery receipt,
/// a call signal) rather than a message — the server cannot tell the two apart, and must not
/// (construct-docs `decisions/notification-extension-reads-only.md`). The flag is the same on
/// every message push, so it says nothing about the one it is on; a build without the extension
/// ignores it.
fn extension_reads_it(activity_type: Option<&str>, is_alert: bool) -> Option<u8> {
    (is_alert && activity_type == Some("new_message")).then_some(1)
}

/// Whether a push is a message alert, the only kind that is held back while a previous one is
/// unconsumed. Contact requests, key-maintenance wakes and silent pushes are never held back, and
/// call pushes do not pass through here at all.
fn is_message_alert(activity_type: Option<&str>, is_alert: bool) -> bool {
    is_alert && activity_type == Some("new_message")
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PushDecision {
    Send,
    /// A message push to this device has not been consumed yet; its banner is still the one the
    /// person will see.
    SkipOutstanding,
}

/// The one decision: a message alert is skipped while a push to the same device is outstanding;
/// every other push is sent regardless of the marker.
pub(crate) fn decide_push(is_message_alert: bool, outstanding: bool) -> PushDecision {
    if is_message_alert && outstanding {
        PushDecision::SkipOutstanding
    } else {
        PushDecision::Send
    }
}

/// A push that never reached the device must not leave its marker behind, or the next envelope
/// would be held back for a banner that was never shown.
async fn release_marker(context: &NotificationServiceContext, device: Option<&str>) {
    if let Some(device) = device
        && let Err(e) = context
            .queue
            .lock()
            .await
            .clear_push_outstanding(device)
            .await
    {
        tracing::warn!(error = %e, "could not clear push-outstanding marker — TTL will");
    }
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

    // `device_id` is read with a runtime query rather than added to the `query!` above: that
    // would change the compile-time-checked statement and its offline data for one column.
    let device_ids: std::collections::HashMap<Vec<u8>, String> = sqlx::query(
        "SELECT device_token_encrypted, device_id FROM device_tokens \
         WHERE user_id = $1 AND enabled = TRUE AND device_id IS NOT NULL",
    )
    .bind(input.user_id)
    .fetch_all(&*context.db_pool)
    .await
    .map(|rows| {
        rows.iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<Vec<u8>, _>("device_token_encrypted").ok()?,
                    r.try_get::<String, _>("device_id").ok()?,
                ))
            })
            .collect()
    })
    // Fail open: without the ids nothing is held back and every device gets its push.
    .unwrap_or_default();

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

        // A device that asked for silent pushes keeps getting only those.
        let alert = push_alert(filter, input.announce, input.activity_type.as_deref());
        // Visible pushes still carry content-available (the builder adds it), so a wake the
        // system does grant still fetches; the app's banner then replaces this one.
        let (push_type, priority) = if alert.is_some() {
            (PushType::Visible, NotificationPriority::High)
        } else {
            (PushType::Silent, NotificationPriority::Low)
        };
        // One banner per unread batch, per device: while a message push to this device is
        // outstanding, the next envelope does not push again. A row with no device id cannot be
        // cleared by a mailbox read, so it is never held back.
        //
        // Fails OPEN: if Redis cannot answer, the push is sent. A duplicate banner is a nuisance;
        // a withheld one is a missed message, and only the marker's TTL would end it.
        let outstanding_for: Option<&str> =
            if is_message_alert(input.activity_type.as_deref(), alert.is_some()) {
                device_ids
                    .get(&token_row.device_token_encrypted)
                    .map(String::as_str)
            } else {
                None
            };
        if let Some(device) = outstanding_for {
            let acquired = context
                .queue
                .lock()
                .await
                .try_mark_push_outstanding(device)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "push-outstanding marker unavailable — sending");
                    true
                });
            if decide_push(true, !acquired) == PushDecision::SkipOutstanding {
                tracing::debug!(
                    user_hash = %user_id_hash,
                    "Message push skipped — previous one unconsumed"
                );
                continue;
            }
        }
        let mutable_content = extension_reads_it(input.activity_type.as_deref(), alert.is_some());
        let payload = ApnsPayload {
            aps: ApsData {
                content_available: Some(1u8),
                sound: alert.as_ref().map(|_| "default".to_string()),
                alert,
                badge: input.badge_count.map(|b| b as u32),
                mutable_content,
            },
            construct: input.activity_type.as_ref().map(|activity| ConstructData {
                notification_type: activity.clone(),
                conversation_id: input.conversation_id.clone(),
            }),
            construct_call: None,
        };
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
            release_marker(context, outstanding_for).await;
            match verdict_after_rejection(environments.len()) {
                RejectionVerdict::Widen => {
                    tracing::warn!(
                        user_hash = %user_id_hash,
                        push_environment = %token_row.push_environment,
                        push_provider = %token_row.push_provider,
                        "APNs: token rejected by its only declared environment — widening to both \
                         rather than deleting; the declaration is the likelier error"
                    );
                    if let Err(db_err) = sqlx::query(
                        "UPDATE device_tokens SET push_environment = $1 \
                         WHERE device_token_encrypted = $2",
                    )
                    .bind(ApnsEnvironments::both().to_string())
                    .bind(&token_row.device_token_encrypted)
                    .execute(&*context.db_pool)
                    .await
                    {
                        tracing::error!(
                            error = %db_err,
                            user_hash = %user_id_hash,
                            "Failed to widen device token environment in DB"
                        );
                    }
                    continue;
                }
                RejectionVerdict::Delete => {
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
            }
        }
        let Some(environment) = succeeded_on else {
            release_marker(context, outstanding_for).await;
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
        // The table carries TWO uniqueness rules — `UNIQUE(user_id, device_token_hash)`
        // from migration 006 and the partial `(user_id, device_id)` index from 025 — but
        // `ON CONFLICT` can name only one target. So a row holding this token under a
        // NULL (or different) device_id is not merely a stale duplicate: the upsert below
        // targets `(user_id, device_id)`, finds nothing to update, attempts an INSERT, and
        // that INSERT violates the token-hash constraint. The whole registration then
        // errors — permanently, on every retry, for that device/token pair.
        //
        // Such rows exist because a client that could not read its device id used to
        // register with an empty one (fixed client-side in messenger 480f7364). Claim the
        // token for this device before upserting; APNs tokens are unique per app install,
        // so any other row holding it is by definition stale.
        // One transaction: a DELETE that commits without its INSERT would leave the user
        // with no token at all — strictly worse than the duplicate we are removing.
        let mut tx = context
            .db_pool
            .begin()
            .await
            .context("Failed to open device token registration transaction")?;

        let orphaned = sqlx::query(
            r#"
            DELETE FROM device_tokens
            WHERE user_id = $1
              AND device_token_hash = $2
              AND device_id IS DISTINCT FROM $3
            "#,
        )
        .bind(input.user_id)
        .bind(&token_hash)
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .context("Failed to clear stale rows holding this device token")?
        .rows_affected();

        if orphaned > 0 {
            tracing::info!(
                user_hash = %user_id_hash,
                rows = orphaned,
                "Claimed device token from stale row(s) not bound to this device"
            );
        }

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
        .execute(&mut *tx)
        .await
        .context("Failed to insert/update device token")?;

        tx.commit()
            .await
            .context("Failed to commit device token registration")?;
    } else {
        // A registration with no device id cannot be addressed per-device: the row it
        // creates is keyed only by the token, and until some later registration supplies a
        // device id (which now claims it, above) nothing can update it in place. Tolerated
        // so an unknown client is not locked out, but it should not happen from our own
        // clients — iOS defers instead (messenger 480f7364). Logged at warn so a client
        // regressing to this is visible rather than merely odd.
        tracing::warn!(
            user_hash = %user_id_hash,
            push_provider = %input.push_provider,
            "Device token registered WITHOUT a device id — row is token-keyed and cannot be \
             addressed per device; the client should defer until its device id exists"
        );

        // Note the DO UPDATE list deliberately omits device_id: if a row for this token
        // already exists under a real device, this must not orphan it.
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
            // Same verdict as a message push. Until 2026-10-29 this path deleted on a
            // rejection from the row's only declared environment — the 2026-08-18 loop
            // `verdict_after_rejection` exists to stop, reopened by any key-rotation wake.
            let (query, action) = match verdict_after_rejection(environments.len()) {
                RejectionVerdict::Widen => (
                    sqlx::query(
                        "UPDATE device_tokens SET push_environment = $1 \
                         WHERE device_token_encrypted = $2",
                    )
                    .bind(ApnsEnvironments::both().to_string())
                    .bind(&token_row.device_token_encrypted),
                    "widening to both",
                ),
                RejectionVerdict::Delete => (
                    sqlx::query("DELETE FROM device_tokens WHERE device_token_encrypted = $1")
                        .bind(&token_row.device_token_encrypted),
                    "deleting",
                ),
            };
            tracing::warn!(
                user_hash = %user_id_hash,
                push_environment = %token_row.push_environment,
                action,
                "APNs token rejected by every declared environment (key-rotation wake)"
            );
            if let Err(db_err) = query.execute(&*context.db_pool).await {
                tracing::error!(
                    error = %db_err,
                    user_hash = %user_id_hash,
                    action,
                    "Failed to update device token after key-rotation wake rejection"
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
            // Same verdict as a message push: a rejection from the only declared environment
            // condemns the pairing, not the token. Disabling here was the 2026-08-18 loop for
            // calls — a mislabelled VoIP token went dark on the first incoming call.
            let (query, action) = match verdict_after_rejection(environments.len()) {
                RejectionVerdict::Widen => (
                    sqlx::query("UPDATE voip_tokens SET push_environment = $1 WHERE id = $2")
                        .bind(ApnsEnvironments::both().to_string())
                        .bind(token_id),
                    "widening to both",
                ),
                RejectionVerdict::Delete => (
                    sqlx::query("UPDATE voip_tokens SET enabled = FALSE WHERE id = $1")
                        .bind(token_id),
                    "disabling",
                ),
            };
            tracing::info!(
                user_hash = %user_id_hash,
                push_environment = %push_environment,
                action,
                "VoIP token rejected by every declared environment"
            );
            if let Err(db_err) = query.execute(&*context.db_pool).await {
                tracing::error!(
                    error = %db_err,
                    user_hash = %user_id_hash,
                    action,
                    "Failed to update VoIP token after APNs rejection"
                );
            }
        } else if let Some(environment) = delivered_on
            && environments.len() > 1
            && let Err(db_err) =
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

#[cfg(test)]
mod rejection_verdict_tests {
    use super::*;

    /// The 2026-08-18 loop: client named one environment, that one rejected, row deleted,
    /// client re-registered the same wrong label. Widening breaks the cycle without an app
    /// update.
    #[test]
    fn single_declared_environment_widens_instead_of_deleting() {
        assert_eq!(verdict_after_rejection(1), RejectionVerdict::Widen);
    }

    /// Both endpoints tried and both said no — nothing left to be wrong about but the token.
    #[test]
    fn both_environments_rejecting_deletes() {
        assert_eq!(verdict_after_rejection(2), RejectionVerdict::Delete);
    }

    /// `ApnsEnvironments::parse_or_both` cannot produce an empty set, but a zero here would
    /// mean "no endpoint was ever asked", which is the one state where deletion is certainly
    /// unjustified.
    #[test]
    fn no_environment_tried_never_deletes() {
        assert_eq!(verdict_after_rejection(0), RejectionVerdict::Widen);
    }
}

#[cfg(test)]
mod blind_alert_tests {
    use super::*;

    fn keys(activity: &str) -> Option<(&'static str, &'static str)> {
        match blind_alert(Some(activity))? {
            AlertData::Localized {
                title_loc_key,
                loc_key,
            } => Some((title_loc_key, loc_key)),
            AlertData::Text { .. } => panic!("a blind alert never carries server-written text"),
        }
    }

    /// Mutation: return `None` for new_message — messages go back to background pushes and
    /// TestFlight banners disappear again.
    #[test]
    fn a_message_is_a_banner() {
        assert_eq!(
            keys("new_message"),
            Some(("construct_app_name", "construct_new_message"))
        );
        assert_eq!(
            keys("contact_request_received"),
            Some(("construct_app_name", "contact_request_received_body"))
        );
    }

    /// A key-maintenance wake that showed a banner would put "New message" on the lock screen
    /// for something that is not one.
    #[test]
    fn maintenance_wakes_stay_silent() {
        for activity in [
            "replenish_prekeys",
            "republish_hybrid_prekeys",
            "rotate_keys",
            "replenish_key_packages",
            "group_dissolved",
            "contact_request_accepted",
            "invite_accepted",
        ] {
            assert!(blind_alert(Some(activity)).is_none(), "{activity}");
        }
        assert!(blind_alert(None).is_none());
    }

    /// Only a message's alert goes to the extension: a contact request is no sealed message to
    /// decrypt, and a background push (the `silent` filter) has no alert to rewrite.
    #[test]
    fn only_a_message_alert_goes_to_the_extension() {
        assert_eq!(extension_reads_it(Some("new_message"), true), Some(1));
        assert_eq!(extension_reads_it(Some("new_message"), false), None);
        assert_eq!(
            extension_reads_it(Some("contact_request_received"), true),
            None
        );
        assert_eq!(extension_reads_it(Some("rotate_keys"), false), None);
        assert_eq!(extension_reads_it(None, true), None);
    }

    /// The flag under the name Apple reads; absent, not zero, when unset.
    #[test]
    fn the_flag_serializes_as_mutable_content() {
        use construct_server_shared::apns::types::ApsData;
        let aps = |mutable_content| ApsData {
            content_available: Some(1),
            alert: blind_alert(Some("new_message")),
            sound: Some("default".to_string()),
            badge: None,
            mutable_content,
        };
        let json = serde_json::to_value(aps(Some(1))).unwrap();
        assert_eq!(json["mutable-content"], 1);
        let json = serde_json::to_value(aps(None)).unwrap();
        assert!(json.get("mutable-content").is_none(), "{json}");
    }

    /// What APNs receives: keys under the names Apple reads, no text of ours.
    #[test]
    fn the_alert_serializes_as_apple_keys() {
        let json = serde_json::to_value(blind_alert(Some("new_message"))).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "title-loc-key": "construct_app_name",
                "loc-key": "construct_new_message"
            })
        );
    }
}

#[cfg(test)]
mod push_outstanding_tests {
    use super::*;

    #[test]
    fn a_second_message_alert_is_skipped_while_one_is_outstanding() {
        assert_eq!(decide_push(true, true), PushDecision::SkipOutstanding);
    }

    #[test]
    fn the_first_message_alert_is_sent() {
        assert_eq!(decide_push(true, false), PushDecision::Send);
    }

    #[test]
    fn other_pushes_ignore_the_marker() {
        assert_eq!(decide_push(false, true), PushDecision::Send);
    }

    #[test]
    fn an_unannounced_push_has_no_banner() {
        assert!(push_alert("visible_all", true, Some("new_message")).is_some());
        assert!(push_alert("visible_all", false, Some("new_message")).is_none());
        assert!(push_alert("silent", true, Some("new_message")).is_none());
    }

    #[test]
    fn only_a_new_message_alert_is_a_message_alert() {
        assert!(is_message_alert(Some("new_message"), true));
        assert!(!is_message_alert(Some("new_message"), false)); // silent device
        assert!(!is_message_alert(Some("contact_request_received"), true));
        assert!(!is_message_alert(None, true));
    }
}
