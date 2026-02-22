// ============================================================================
// Notifications Routes - Phase 2.6.5
// ============================================================================
//
// Endpoints:
// - POST /api/v1/notifications/register-device - Register device token
// - POST /api/v1/notifications/unregister-device - Unregister device token
// - PUT /api/v1/notifications/preferences - Update notification preferences
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::apns::DeviceTokenEncryption;
use crate::context::AppContext;
use crate::routes::extractors::TrustedUser;
use crate::utils::log_safe_id;
use construct_error::AppError;

/// Request body for device token registration
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    /// Device token (APNs token)
    pub device_token: String,
    /// Optional device name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// Notification filter preference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_filter: Option<String>,
}

/// Request body for device token unregistration
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnregisterDeviceRequest {
    /// Device token to unregister
    pub device_token: String,
}

/// Request body for notification preferences update
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePreferencesRequest {
    /// Device token
    pub device_token: String,
    /// Notification filter preference
    pub notification_filter: String,
    /// Whether notifications are enabled
    pub enabled: bool,
}

/// POST /api/v1/notifications/register-device
/// Register a device token for push notifications
///
/// Security:
/// - Requires JWT authentication (verified by Gateway, identity via X-User-Id header)
/// - Device token is encrypted before storage
pub async fn register_device(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id_str = user_id.to_string();
    let user_id_hash = log_safe_id(&user_id_str, &app_context.config.logging.hash_salt);

    // Validate device token format
    if request.device_token.is_empty() || request.device_token.len() > 128 {
        tracing::warn!(
            user_hash = %user_id_hash,
            "Invalid device token format"
        );
        return Err(AppError::Validation(
            "Device token format is invalid".to_string(),
        ));
    }

    // Validate notification filter
    let filter = request
        .notification_filter
        .unwrap_or_else(|| "silent".to_string());
    let valid_filters = [
        "silent",
        "visible_all",
        "visible_dm",
        "visible_mentions",
        "visible_contacts",
    ];
    if !valid_filters.contains(&filter.as_str()) {
        tracing::warn!(
            user_hash = %user_id_hash,
            filter = %filter,
            "Invalid notification filter"
        );
        return Err(AppError::Validation(format!(
            "Invalid notification filter. Must be one of: {:?}",
            valid_filters
        )));
    }

    tracing::debug!(
        user_hash = %user_id_hash,
        filter = %filter,
        "Registering device token"
    );

    // Encrypt device token and device name
    let token_hash = DeviceTokenEncryption::hash_token(&request.device_token);
    let token_encrypted = app_context
        .token_encryption
        .encrypt(&request.device_token)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to encrypt device token"
            );
            AppError::Unknown(e)
        })?;

    let name_encrypted = if let Some(ref name) = request.device_name {
        Some(app_context.token_encryption.encrypt(name).map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to encrypt device name"
            );
            AppError::Unknown(e)
        })?)
    } else {
        None
    };

    // Insert or update device token in database
    let query_result = sqlx::query(
        r#"
        INSERT INTO device_tokens (user_id, device_token_hash, device_token_encrypted, device_name_encrypted, notification_filter, enabled)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        ON CONFLICT (user_id, device_token_hash)
        DO UPDATE SET
            device_name_encrypted = EXCLUDED.device_name_encrypted,
            notification_filter = EXCLUDED.notification_filter,
            enabled = TRUE
        "#,
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(&token_encrypted)
    .bind(&name_encrypted)
    .bind(&filter)
    .execute(&*app_context.db_pool)
    .await;

    match query_result {
        Ok(_) => {
            tracing::info!(
                user_hash = %user_id_hash,
                "Device token registered successfully"
            );
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "message": "Device token registered"
                })),
            ))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to register device token"
            );
            Err(AppError::Unknown(e.into()))
        }
    }
}

/// POST /api/v1/notifications/unregister-device
/// Unregister a device token
///
/// Security:
/// - Requires JWT authentication (verified by Gateway, identity via X-User-Id header)
pub async fn unregister_device(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<UnregisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id_str = user_id.to_string();
    let user_id_hash = log_safe_id(&user_id_str, &app_context.config.logging.hash_salt);

    // Hash token for lookup
    let token_hash = DeviceTokenEncryption::hash_token(&request.device_token);

    // Delete device token from database
    let query_result = sqlx::query(
        r#"
        DELETE FROM device_tokens
        WHERE user_id = $1 AND device_token_hash = $2
        "#,
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&*app_context.db_pool)
    .await;

    match query_result {
        Ok(result) => {
            if result.rows_affected() > 0 {
                tracing::info!(
                    user_hash = %user_id_hash,
                    "Device token unregistered successfully"
                );
                Ok((
                    StatusCode::OK,
                    Json(json!({
                        "status": "ok",
                        "message": "Device token unregistered"
                    })),
                ))
            } else {
                tracing::warn!(
                    user_hash = %user_id_hash,
                    "Device token not found"
                );
                Err(AppError::Validation("Device token not found".to_string()))
            }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to unregister device token"
            );
            Err(AppError::Unknown(e.into()))
        }
    }
}

/// PUT /api/v1/notifications/preferences
/// Update notification preferences for a device
///
/// Security:
/// - Requires JWT authentication (verified by Gateway, identity via X-User-Id header)
pub async fn update_preferences(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<UpdatePreferencesRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id_str = user_id.to_string();
    let user_id_hash = log_safe_id(&user_id_str, &app_context.config.logging.hash_salt);

    // Validate notification filter
    let valid_filters = [
        "silent",
        "visible_all",
        "visible_dm",
        "visible_mentions",
        "visible_contacts",
    ];
    if !valid_filters.contains(&request.notification_filter.as_str()) {
        tracing::warn!(
            user_hash = %user_id_hash,
            filter = %request.notification_filter,
            "Invalid notification filter"
        );
        return Err(AppError::Validation(format!(
            "Invalid notification filter. Must be one of: {:?}",
            valid_filters
        )));
    }

    tracing::debug!(
        user_hash = %user_id_hash,
        filter = %request.notification_filter,
        enabled = request.enabled,
        "Updating device token preferences"
    );

    // Hash token for lookup
    let token_hash = DeviceTokenEncryption::hash_token(&request.device_token);

    // Update device token preferences
    let query_result = sqlx::query(
        r#"
        UPDATE device_tokens
        SET notification_filter = $3, enabled = $4
        WHERE user_id = $1 AND device_token_hash = $2
        "#,
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(&request.notification_filter)
    .bind(request.enabled)
    .execute(&*app_context.db_pool)
    .await;

    match query_result {
        Ok(result) => {
            if result.rows_affected() > 0 {
                tracing::info!(
                    user_hash = %user_id_hash,
                    "Device token preferences updated successfully"
                );
                Ok((
                    StatusCode::OK,
                    Json(json!({
                        "status": "ok",
                        "message": "Preferences updated"
                    })),
                ))
            } else {
                tracing::warn!(
                    user_hash = %user_id_hash,
                    "Device token not found"
                );
                Err(AppError::Validation("Device token not found".to_string()))
            }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to update device token preferences"
            );
            Err(AppError::Unknown(e.into()))
        }
    }
}
