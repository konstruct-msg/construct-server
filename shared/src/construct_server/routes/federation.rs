// ============================================================================
// Federation Routes
// ============================================================================
//
// Endpoints:
// - GET /.well-known/konstruct - Federation discovery
// - GET /federation/health - Federation health check
// - POST /federation/v1/messages - Receive federated message from remote server
// - GET /federation/v1/keys/:user_id - Get user's key bundle (for federation)
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::db;
use crate::utils::log_safe_id;
use construct_error::AppError;

/// GET /.well-known/construct-server
/// gRPC Service Discovery Endpoint (Hybrid Discovery Protocol v1.0)
/// Returns gRPC service endpoints, capabilities, and server public key
///
/// This endpoint implements Priority 2 of the Hybrid Discovery Protocol:
/// - Priority 1: DNS SRV records (optional, fastest)
/// - Priority 2: .well-known REST endpoint (PRIMARY, this endpoint)
/// - Priority 3: Standard port fallback (emergency)
///
/// Cache-Control: 1 hour (CDN-friendly)
pub async fn well_known_construct_server(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    use axum::http::header;

    // Get server public key for federation
    let public_key = app_context
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    // Build gRPC service discovery response
    let domain = &app_context.config.instance_domain;

    // TLS enabled in production (when public key is configured)
    let tls_enabled = public_key.is_some();

    let discovery_info = json!({
        "version": "1.0",
        "protocol": "grpc",
        "server": {
            "domain": domain,
            "version": env!("CARGO_PKG_VERSION"),
            "public_key": public_key,
        },
        "grpc_endpoint": format!("{}:443", domain),
        "services": [
            "auth.AuthService",
            "user.UserService",
            "messaging.MessagingService",
            "notification.NotificationService",
            "invite.InviteService",
            "media.MediaService"
        ],
        "federation": {
            "enabled": app_context.config.federation_enabled,
            "protocol_version": "1.0",
            "public_key": public_key,
            "s2s_endpoint": format!("{}:443", domain),
            "tls": tls_enabled
        },
        "capabilities": {
            "max_message_size_bytes": 100_000,
            "max_file_size_bytes": 100_000_000,
            "supports_streaming": true,
            "supports_grpc_web": true,
            "supports_pq_crypto": false
        },
        "limits": {
            "max_message_size_bytes": 100_000,
            "max_media_size_bytes": 100_000_000,
            "rate_limit_messages_per_hour": app_context.config.security.max_messages_per_hour,
            "rate_limit_pow_per_hour": 10
        }
    });

    // Set Cache-Control header (1 hour, CDN-friendly)
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(discovery_info),
    ))
}

/// GET /.well-known/konstruct
/// Federation discovery endpoint (Legacy)
/// Returns server capabilities and federation endpoints
pub async fn well_known_konstruct(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    // Get public key if server signer is configured
    let public_key = app_context
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    let info = json!({
        "server": app_context.config.instance_domain,
        "version": "1.0",
        "public_key": public_key,
        "federation": {
            "enabled": app_context.config.federation_enabled,
            "protocol_version": "1.0",
            "public_key": public_key,
            "endpoints": {
                "messages": format!("https://{}/federation/v1/messages", app_context.config.instance_domain),
                "health": format!("https://{}/federation/health", app_context.config.instance_domain),
                "keys": format!("https://{}/federation/v1/keys", app_context.config.instance_domain),
                "key_format": "GET /federation/v1/keys/{user_id}"
            }
        },
        "features": [
            "end_to_end_encryption",
            "double_ratchet",
            "message_delivery",
            "offline_queue",
            "server_signatures"
        ],
        "limits": {
            "max_message_size": 100_000,
            "rate_limit_per_hour": app_context.config.security.max_messages_per_hour
        }
    });

    Ok((StatusCode::OK, Json(info)))
}

/// GET /federation/health
/// Federation health check
pub async fn federation_health(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    let health = json!({
        "status": "healthy",
        "instance": app_context.config.instance_domain,
        "federation_enabled": app_context.config.federation_enabled,
        "version": "1.0"
    });

    Ok((StatusCode::OK, Json(health)))
}

/// POST /federation/v1/messages
/// Receive federated message from remote server
///
/// This endpoint receives messages from other federation servers when
/// the recipient is on this instance.
pub async fn receive_federated_message(
    State(app_context): State<Arc<AppContext>>,
    body: axum::body::Body,
) -> Result<impl IntoResponse, AppError> {
    // Read body bytes
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| AppError::Hyper(format!("Failed to read body: {}", e)))?;

    // Use the helper function that accepts bytes directly
    use crate::handlers::federation::receive_federated_message_bytes;
    let response = receive_federated_message_bytes(&app_context, body_bytes).await?;

    // Convert hyper::Response to axum response
    let (parts, body) = response.into_parts();
    use http_body_util::BodyExt;
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| AppError::Hyper(format!("Failed to collect response body: {}", e)))?
        .to_bytes();

    let mut axum_response = axum::response::Response::builder().status(parts.status);

    // Copy headers
    for (key, value) in parts.headers {
        if let (Some(name), Ok(val)) = (key, axum::http::HeaderValue::from_bytes(value.as_bytes()))
        {
            axum_response = axum_response.header(name, val);
        }
    }

    axum_response
        .body(axum::body::Body::from(body_bytes.to_vec()))
        .map_err(|e| AppError::Hyper(format!("Failed to build response: {}", e)))
}

/// GET /federation/v1/keys/:user_id
/// Get user's key bundle for federation
///
/// This endpoint allows remote federation servers to fetch key bundles
/// for users on this instance. Used when sending federated messages.
///
/// Security:
/// - Server-to-server authentication via Ed25519 signatures (in message envelope)
/// - Rate limiting (via middleware)
/// - Caching support (5 minute TTL)
///
/// Format: /federation/v1/keys/{uuid}
/// Example: /federation/v1/keys/550e8400-e29b-41d4-a716-446655440000
pub async fn get_federation_keys(
    State(app_context): State<Arc<AppContext>>,
    Path(user_id_str): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Parse user_id
    let user_id = match Uuid::parse_str(&user_id_str) {
        Ok(id) => id,
        Err(_) => {
            tracing::warn!(
                user_id = %user_id_str,
                "Invalid user ID format in federation keys request"
            );
            return Err(AppError::Validation(
                "Invalid user ID format. Expected UUID.".to_string(),
            ));
        }
    };

    // Check cache first (5 minute TTL)
    {
        let mut queue = app_context.queue.lock().await;
        if let Ok(Some(cached_json)) = queue
            .get_cached_federation_key_bundle(&user_id.to_string())
            .await
            && let Ok(bundle_json) = serde_json::from_str::<serde_json::Value>(&cached_json)
        {
            drop(queue);
            tracing::debug!(
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Returning cached key bundle for federation"
            );
            return Ok((StatusCode::OK, Json(bundle_json)));
        }
        drop(queue);
    }

    // Fetch from database
    let (bundle, username) = match db::get_key_bundle(&app_context.db_pool, &user_id).await {
        Ok(Some((bundle, username))) => (bundle, username),
        Ok(None) => {
            tracing::debug!(
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Key bundle not found for federation request"
            );
            // Return 404 Not Found for missing key bundle
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "User key bundle not found"
                })),
            ));
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to fetch key bundle from database"
            );
            return Err(AppError::Unknown(e));
        }
    };

    // Build response
    let response = json!({
        "user_id": user_id.to_string(),
        "username": username,
        "bundle": {
            "master_identity_key": bundle.master_identity_key,
            "bundle_data": bundle.bundle_data,
            "signature": bundle.signature,
        }
    });

    // Cache the response (5 minutes TTL)
    {
        let mut queue = app_context.queue.lock().await;
        let cache_value = serde_json::to_string(&response).unwrap_or_default();

        if let Err(e) = queue
            .cache_federation_key_bundle(
                &user_id.to_string(),
                &cache_value,
                300, // 5 minutes TTL
            )
            .await
        {
            tracing::warn!(
                error = %e,
                "Failed to cache federation key bundle (non-critical)"
            );
        }
        drop(queue);
    }

    tracing::debug!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Returning key bundle for federation"
    );

    Ok((StatusCode::OK, Json(response)))
}
