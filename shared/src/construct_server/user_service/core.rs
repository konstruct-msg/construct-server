use std::sync::Arc;

use crate::context::AppContext;
use crate::db;
use crate::routes::keys::{KeyBundleResponse, PublicKeyResponse};
use crate::routes::request_signing::{
    compute_body_hash, extract_request_signature, verify_request_signature,
};
use crate::utils::log_safe_id;
use crate::{audit::AuditLogger, utils::extract_client_ip};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::{BundleData, ServerCryptoValidator, UploadableKeyBundle};
use construct_error::AppError;
use serde_json::{Value, json};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AccountInfoData {
    pub user_id: String,
    pub username: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateAccountInput {
    pub username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateVerifyingKeyInput {
    pub verifying_key: String,
    pub reason: Option<String>,
}

pub async fn get_account_info(
    app_context: Arc<AppContext>,
    user_id: Uuid,
) -> Result<AccountInfoData, AppError> {
    let user_record = db::get_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to fetch user from database"
            );
            AppError::Unknown(e)
        })?;

    let user_record = user_record.ok_or_else(|| {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "User not found in database"
        );
        // SECURITY: Don't reveal whether user exists - use generic error
        AppError::Auth("Session is invalid or expired".to_string())
    })?;

    tracing::debug!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Account information retrieved"
    );

    Ok(AccountInfoData {
        user_id: user_record.id.to_string(),
        username: user_record.username,
        created_at: None,
    })
}

pub async fn update_account(
    app_context: Arc<AppContext>,
    user_id: Uuid,
    input: UpdateAccountInput,
) -> Result<(), AppError> {
    // Fetch current user (passwordless)
    let _user_record = db::get_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch user");
            AppError::Unknown(e)
        })?
        .ok_or_else(
            || // SECURITY: Don't reveal whether user exists - use generic error
            AppError::Auth("Session is invalid or expired".to_string()),
        )?;

    // Update username if provided
    if let Some(new_username) = &input.username {
        let normalized = new_username.trim().to_lowercase();
        let username_to_store = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };

        if let Some(ref username) = username_to_store {
            if username.len() < 3 || username.len() > 20 {
                return Err(AppError::Validation(
                    "Username must be 3-20 characters".to_string(),
                ));
            }
            if !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(AppError::Validation(
                    "Username can only contain letters, numbers, and underscores".to_string(),
                ));
            }

            if let Ok(Some(existing_user)) =
                db::get_user_by_username(&app_context.db_pool, username).await
                && existing_user.id != user_id
            {
                return Err(AppError::Validation(
                    "Username is already taken".to_string(),
                ));
            }
        }

        db::update_user_username(&app_context.db_pool, &user_id, username_to_store.as_deref())
            .await
            .map_err(AppError::Unknown)?;
        return Ok(());
    }

    // If no updates were requested
    if input.username.is_none() {
        return Err(AppError::Validation(
            "No update fields provided".to_string(),
        ));
    }

    Ok(())
}

pub async fn get_public_key_bundle(
    app_context: Arc<AppContext>,
    authenticated_user_id: Uuid,
    user_id_str: String,
) -> Result<(StatusCode, Json<PublicKeyResponse>), AppError> {
    {
        let mut queue = app_context.queue.lock().await;
        match queue
            .increment_message_count(&authenticated_user_id.to_string())
            .await
        {
            Ok(count) => {
                let max_messages = app_context.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        user_hash = %log_safe_id(&authenticated_user_id.to_string(), &app_context.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Key bundle request rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} requests per hour",
                        max_messages
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit for key bundle request");
            }
        }
        drop(queue);
    }

    let user_id = Uuid::parse_str(&user_id_str)
        .map_err(|_| AppError::Validation("Invalid user ID format".to_string()))?;

    match db::get_extended_key_bundle(&app_context.db_pool, &user_id).await {
        Ok(Some(ext_bundle)) => {
            tracing::debug!(
                target_user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Key bundle retrieved (spec format)"
            );

            let response = PublicKeyResponse {
                key_bundle: KeyBundleResponse {
                    bundle_data: ext_bundle.bundle.bundle_data,
                    master_identity_key: ext_bundle.identity_key,
                    signature: ext_bundle.bundle.signature,
                },
                username: ext_bundle.username,
                verifying_key: ext_bundle.verifying_key,
            };

            Ok((StatusCode::OK, Json(response)))
        }
        Ok(None) => {
            tracing::warn!(
                target_user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Key bundle not found"
            );
            Err(AppError::PublicKeyNotFound)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                target_user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Database error"
            );
            Err(AppError::Unknown(e))
        }
    }
}

pub async fn upload_keys(
    app_context: Arc<AppContext>,
    user_id: Uuid,
    headers: HeaderMap,
    bundle: UploadableKeyBundle,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let client_ip_str = extract_client_ip(&headers, None);
    let client_ip: Option<IpAddr> = client_ip_str.parse().ok();
    let user_id_hash = log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt);

    if let Err(e) = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false) {
        let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
            .await
            .ok()
            .flatten()
            .map(|user| {
                log_safe_id(
                    user.username.as_deref().unwrap_or("unknown"),
                    &app_context.config.logging.hash_salt,
                )
            });

        AuditLogger::log_key_rotation(
            user_id_hash.clone(),
            username_hash,
            client_ip,
            false,
            Some(format!("Key bundle validation failed: {}", e)),
        );

        tracing::warn!(
            error = %e,
            user_hash = %user_id_hash,
            "Key bundle validation failed"
        );
        return Err(AppError::Validation(e.to_string()));
    }

    let bundle_data_bytes = BASE64.decode(&bundle.bundle_data).map_err(|e| {
        tracing::warn!(error = %e, "Failed to decode bundle_data");
        AppError::Validation("Invalid bundle_data encoding".to_string())
    })?;

    let bundle_data: BundleData = match prost::Message::decode(bundle_data_bytes.as_slice()) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decode bundle_data as protobuf");
            return Err(AppError::Validation(
                "Invalid bundle_data format".to_string(),
            ));
        }
    };

    if bundle_data.user_id != user_id.to_string() {
        let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
            .await
            .ok()
            .flatten()
            .map(|user| {
                log_safe_id(
                    user.username.as_deref().unwrap_or("unknown"),
                    &app_context.config.logging.hash_salt,
                )
            });

        AuditLogger::log_key_rotation(
            user_id_hash.clone(),
            username_hash,
            client_ip,
            false,
            Some(format!(
                "user_id mismatch: bundle contains '{}' but authenticated user is '{}'",
                bundle_data.user_id, user_id
            )),
        );

        tracing::warn!(
            authenticated_user = %user_id,
            bundle_user_id = %bundle_data.user_id,
            user_hash = %user_id_hash,
            "user_id mismatch: authenticated user attempting to upload bundle for different user"
        );
        return Err(AppError::Auth(
            "user_id in bundle does not match authenticated user".to_string(),
        ));
    }

    if app_context.config.security.request_signing_required {
        let request_sig = extract_request_signature(&headers).ok_or_else(|| {
            AuditLogger::log_key_rotation(
                user_id_hash.clone(),
                None,
                client_ip,
                false,
                Some("Request signature missing for key upload".to_string()),
            );

            tracing::warn!(
                user_hash = %user_id_hash,
                "Request signature missing for key upload"
            );
            AppError::Validation(
                "Request signature is required for this operation. Please sign the request with your master_identity_key.".to_string(),
            )
        })?;

        let body_json = serde_json::to_string(&bundle).map_err(|e| {
            tracing::error!(error = %e, "Failed to serialize bundle for signature verification");
            AppError::Unknown(e.into())
        })?;
        let body_hash = compute_body_hash(body_json.as_bytes());

        match verify_request_signature(
            &bundle.master_identity_key,
            "POST",
            "/keys/upload",
            request_sig.timestamp,
            &body_hash,
            &request_sig.signature,
        ) {
            Ok(()) => {
                tracing::debug!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    "Request signature verified"
                );
            }
            Err(e) => {
                let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|user| {
                        log_safe_id(
                            user.username.as_deref().unwrap_or("unknown"),
                            &app_context.config.logging.hash_salt,
                        )
                    });

                AuditLogger::log_key_rotation(
                    user_id_hash.clone(),
                    username_hash,
                    client_ip,
                    false,
                    Some(format!("Request signature verification failed: {}", e)),
                );

                tracing::warn!(
                    user_hash = %user_id_hash,
                    error = %e,
                    "Request signature verification failed"
                );
                return Err(AppError::Validation(format!(
                    "Request signature verification failed: {}",
                    e
                )));
            }
        }

        use subtle::ConstantTimeEq;
        if !bool::from(
            request_sig
                .public_key
                .as_bytes()
                .ct_eq(bundle.master_identity_key.as_bytes()),
        ) {
            let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
                .await
                .ok()
                .flatten()
                .map(|user| {
                    log_safe_id(
                        user.username.as_deref().unwrap_or("unknown"),
                        &app_context.config.logging.hash_salt,
                    )
                });

            AuditLogger::log_key_rotation(
                user_id_hash.clone(),
                username_hash,
                client_ip,
                false,
                Some(
                    "Request signature public key does not match bundle master_identity_key"
                        .to_string(),
                ),
            );

            tracing::warn!(
                user_hash = %user_id_hash,
                "Request signature public key does not match bundle master_identity_key"
            );
            return Err(AppError::Validation(
                "Request signature public key must match bundle master_identity_key".to_string(),
            ));
        }
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    let nonce = bundle.nonce.as_deref().unwrap_or(&request_id);
    let timestamp = bundle
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let content_for_replay = &bundle.bundle_data;

    {
        let mut queue = app_context.queue.lock().await;
        const MAX_AGE_SECONDS: i64 = 300;
        match queue
            .check_replay_with_timestamp(
                &request_id,
                content_for_replay,
                nonce,
                timestamp,
                MAX_AGE_SECONDS,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                drop(queue);
                let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|user| {
                        log_safe_id(
                            user.username.as_deref().unwrap_or("unknown"),
                            &app_context.config.logging.hash_salt,
                        )
                    });

                AuditLogger::log_key_rotation(
                    user_id_hash.clone(),
                    username_hash,
                    client_ip,
                    false,
                    Some(format!(
                        "Replay attack detected for key upload (request_id: {})",
                        request_id
                    )),
                );

                tracing::warn!(
                    user_hash = %user_id_hash,
                    request_id = %request_id,
                    "Replay attack detected for key upload"
                );
                return Err(AppError::Validation(
                    "This request was already processed or is too old. Please generate a new request."
                        .to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check replay protection");
            }
        }
        drop(queue);
    }

    let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
        .await
        .ok()
        .flatten()
        .map(|user| {
            log_safe_id(
                user.username.as_deref().unwrap_or("unknown"),
                &app_context.config.logging.hash_salt,
            )
        });

    let store_result = db::store_key_bundle(&app_context.db_pool, &user_id, &bundle).await;
    match &store_result {
        Ok(_) => {
            AuditLogger::log_key_rotation(
                user_id_hash.clone(),
                username_hash.clone(),
                client_ip,
                true,
                Some("Key bundle uploaded successfully".to_string()),
            );
            tracing::info!(
                user_hash = %user_id_hash,
                "Key bundle uploaded successfully"
            );
        }
        Err(e) => {
            AuditLogger::log_key_rotation(
                user_id_hash.clone(),
                username_hash.clone(),
                client_ip,
                false,
                Some(format!("Failed to store key bundle: {}", e)),
            );
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to store key bundle"
            );
        }
    }

    store_result.map_err(AppError::Unknown)?;

    let mut queue = app_context.queue.lock().await;
    if let Err(e) = queue
        .invalidate_key_bundle_cache(&user_id.to_string())
        .await
    {
        tracing::warn!(error = %e, "Failed to invalidate key bundle cache");
    }
    drop(queue);

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))))
}

pub async fn update_verifying_key(
    app_context: Arc<AppContext>,
    user_id: Uuid,
    headers: HeaderMap,
    input: UpdateVerifyingKeyInput,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let user_id_hash = log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt);
    let client_ip_str = extract_client_ip(&headers, None);
    let client_ip: Option<IpAddr> = client_ip_str.parse().ok();

    let verifying_key_bytes = BASE64.decode(&input.verifying_key).map_err(|e| {
        tracing::warn!(
            error = %e,
            user_hash = %user_id_hash,
            "Invalid verifying key encoding"
        );
        AppError::Validation("Invalid verifying key: must be base64-encoded".to_string())
    })?;

    if verifying_key_bytes.len() != 32 {
        tracing::warn!(
            user_hash = %user_id_hash,
            key_len = verifying_key_bytes.len(),
            "Invalid verifying key length"
        );
        return Err(AppError::Validation(
            "Invalid verifying key: must be 32 bytes (Ed25519 public key)".to_string(),
        ));
    }

    let device = db::get_user_primary_device(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_hash = %user_id_hash, "Failed to get user's device");
            AppError::Unknown(e)
        })?;

    let Some(device) = device else {
        tracing::warn!(user_hash = %user_id_hash, "No device found for user");
        return Err(AppError::NotFound("No device found for user".to_string()));
    };

    match db::update_device_verifying_key(
        &app_context.db_pool,
        &device.device_id,
        &verifying_key_bytes,
    )
    .await
    {
        Ok(_) => {
            let username_hash = db::get_user_by_id(&app_context.db_pool, &user_id)
                .await
                .ok()
                .flatten()
                .map(|user| {
                    log_safe_id(
                        user.username.as_deref().unwrap_or("unknown"),
                        &app_context.config.logging.hash_salt,
                    )
                });

            AuditLogger::log_key_rotation(
                user_id_hash.clone(),
                username_hash,
                client_ip,
                true,
                Some(format!(
                    "Verifying key updated. Reason: {}",
                    input.reason.as_deref().unwrap_or("not specified")
                )),
            );

            tracing::info!(
                user_hash = %user_id_hash,
                reason = ?input.reason,
                "Verifying key updated successfully"
            );

            Ok((StatusCode::OK, Json(json!({"status": "ok"}))))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to update verifying key"
            );
            Err(AppError::Unknown(e))
        }
    }
}
