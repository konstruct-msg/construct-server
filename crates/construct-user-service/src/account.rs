// ============================================================================
// Account Management Routes
// ============================================================================

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::core;
use construct_context::AppContext;
use construct_db as db;
use construct_error::AppError;
use construct_extractors::TrustedUser;
use construct_utils::{extract_client_ip, log_safe_id};

/// Account information response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// User ID (UUID)
    pub user_id: String,
    /// Username (optional in passwordless architecture)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Account creation timestamp (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// GET /api/v1/account
pub async fn get_account(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let info = core::get_account_info(app_context, user.0).await?;

    Ok((
        StatusCode::OK,
        Json(AccountInfo {
            user_id: info.user_id,
            username: info.username,
            created_at: info.created_at,
        }),
    ))
}

/// Request body for account update
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccountRequest {
    /// New username (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// PUT /api/v1/account
pub async fn update_account(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    _headers: HeaderMap, // Reserved for future request signing
    Json(request): Json<UpdateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    core::update_account(
        app_context,
        user.0,
        core::UpdateAccountInput {
            username: request.username,
        },
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Account updated successfully"
        })),
    ))
}

// NOTE: Legacy DELETE /api/v1/account removed in Phase 5.0.1
// Use device-signed deletion instead:
// - GET /api/v1/users/me/delete-challenge
// - POST /api/v1/users/me/delete-confirm
// See: account_deletion.rs

// ============================================================================
// Username Availability Check
// ============================================================================

/// Query parameters for username availability check
#[derive(Debug, Deserialize)]
pub struct UsernameAvailabilityQuery {
    pub username: String,
}

/// Response for username availability check
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameAvailabilityResponse {
    /// Original username as provided by client
    pub username: String,
    /// Normalized username (lowercase, trimmed)
    pub normalized: String,
    /// Whether the username is available
    pub available: bool,
}

/// Error response for username validation
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameValidationError {
    pub error: String,
    pub message: String,
}

/// Rate limit error response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitError {
    pub error: String,
    pub retry_after_seconds: i64,
}

/// GET /api/v1/users/username/availability?username=<string>
pub async fn check_username_availability(
    State(app_context): State<Arc<AppContext>>,
    headers: HeaderMap,
    Query(query): Query<UsernameAvailabilityQuery>,
) -> Result<impl IntoResponse, AppError> {
    let client_ip = extract_client_ip(&headers, None);
    let device_id = headers
        .get("X-Device-Id")
        .or_else(|| headers.get("X-Client-Id"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    // 1. Rate limiting (10 requests/min per IP)
    {
        let mut queue = app_context.queue.lock().await;
        let rate_key = format!("username_check:ip:{}", client_ip);
        match queue.increment_rate_limit(&rate_key, 60).await {
            Ok(count) => {
                if count > 10 {
                    drop(queue);
                    tracing::warn!(
                        ip = %client_ip,
                        count = count,
                        "Username availability rate limit exceeded (IP)"
                    );
                    return Ok((
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({
                            "error": "rate_limited",
                            "retryAfterSeconds": 60
                        })),
                    ));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit");
            }
        }

        // Rate limit per device (if provided)
        if device_id != "unknown" {
            let device_key = format!("username_check:device:{}", device_id);
            match queue.increment_rate_limit(&device_key, 60).await {
                Ok(count) => {
                    if count > 10 {
                        drop(queue);
                        tracing::warn!(
                            device_id = %device_id,
                            count = count,
                            "Username availability rate limit exceeded (device)"
                        );
                        return Ok((
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(json!({
                                "error": "rate_limited",
                                "retryAfterSeconds": 60
                            })),
                        ));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check device rate limit");
                }
            }
        }
        drop(queue);
    }

    // 2. Normalize username (trim + lowercase)
    let original = query.username.clone();
    let normalized = query.username.trim().to_lowercase();

    // 3. Validate format: ^[a-z0-9_]{3,30}$
    if normalized.len() < 3 || normalized.len() > 30 {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "invalid_username",
                "message": "Username must be 3-30 characters long."
            })),
        ));
    }

    if !normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "invalid_username",
                "message": "Username can only contain letters, numbers, and underscores."
            })),
        ));
    }

    // 4. Anti-enumeration: add slight random jitter (10-50ms)
    let jitter_ms = rand::random::<u64>() % 40 + 10;
    tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;

    // 5. Check database: compute HMAC hash and look for a matching row.
    //    The server never stores plaintext usernames (migration 034), so the check
    //    is a hash equality test — exact match only, no substring search.
    use construct_crypto::hash_username;
    let secret = &app_context.config.security.username_hmac_secret;
    let hash = hash_username(secret, &normalized);

    let available = match db::get_user_by_username_hash(&app_context.db_pool, &hash).await {
        Ok(None) => true,
        Ok(Some(_)) => false,
        Err(e) => {
            tracing::error!(error = %e, "Database error checking username");
            return Err(AppError::Unknown(e));
        }
    };

    // 6. Log mass check attempts (for audit)
    tracing::debug!(
        ip = %client_ip,
        device_id = %device_id,
        username_hash = %log_safe_id(&normalized, &app_context.config.logging.hash_salt),
        available = available,
        "Username availability check"
    );

    // 7. Return response
    Ok((
        StatusCode::OK,
        Json(json!({
            "username": original,
            "normalized": normalized,
            "available": available
        })),
    ))
}
