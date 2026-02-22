// ============================================================================
// Federation Handlers - Server-to-Server Protocol
// ============================================================================
//
// Implements federation protocol for cross-instance messaging:
// 1. Discovery: .well-known/konstruct endpoint
// 2. Receive: /federation/v1/messages endpoint (incoming from remote servers)
// 3. Health: Server status and capabilities
//
// ============================================================================

use crate::{
    context::AppContext,
    federation::{FederatedEnvelope, ServerSigner},
    kafka::KafkaMessageEnvelope,
    utils::{add_security_headers, log_safe_id},
};
use bytes::Bytes;
use construct_error::AppError;
use construct_types::{ChatMessage, UserId};
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Incoming as IncomingBody};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn json_response(status: StatusCode, body: serde_json::Value) -> hyper::Response<Full<Bytes>> {
    let body_str = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    let mut response = hyper::Response::new(Full::new(Bytes::from(body_str)));
    *response.status_mut() = status;

    // SECURITY: Handle header parsing errors gracefully
    match "application/json".parse() {
        Ok(content_type) => {
            response.headers_mut().insert("Content-Type", content_type);
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse Content-Type header (this should never happen)");
            // This should never happen, but if it does, we continue without the header
        }
    }

    // SECURITY: Add security headers to protect against XSS, clickjacking, etc.
    // Assume HTTPS for federation endpoints (they should always use HTTPS)
    add_security_headers(response.headers_mut(), true);

    response
}

/// Federation discovery endpoint
/// Served at: /.well-known/konstruct
///
/// Returns server capabilities and federation endpoints
pub async fn well_known_konstruct(
    ctx: &AppContext,
) -> Result<hyper::Response<Full<Bytes>>, AppError> {
    // Get public key if server signer is configured
    let public_key = ctx
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    let info = json!({
        "server": ctx.config.instance_domain,
        "version": "1.0",
        "public_key": public_key,
        "federation": {
            "enabled": ctx.config.federation_enabled,
            "protocol_version": "1.0",
            "public_key": public_key,
            "endpoints": {
                "messages": format!("https://{}/federation/v1/messages", ctx.config.instance_domain),
                "health": format!("https://{}/federation/health", ctx.config.instance_domain),
                "keys": format!("https://{}/federation/v1/keys", ctx.config.instance_domain)
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
            "rate_limit_per_hour": ctx.config.security.max_messages_per_hour
        }
    });

    Ok(json_response(StatusCode::OK, info))
}

/// Federation health check
/// Served at: /federation/health
pub async fn federation_health(ctx: &AppContext) -> Result<hyper::Response<Full<Bytes>>, AppError> {
    let health = json!({
        "status": "healthy",
        "instance": ctx.config.instance_domain,
        "federation_enabled": ctx.config.federation_enabled,
        "version": "1.0"
    });

    Ok(json_response(StatusCode::OK, health))
}

/// Receive federated message from remote server
/// Served at: POST /federation/v1/messages
///
/// Remote server sends message here when recipient is on this instance
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedMessageRequest {
    pub message_id: String,
    pub from: String, // alice@remote.konstruct.cc
    pub to: String,   // bob@eu.konstruct.cc
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: String, // base64
    pub message_number: u32,
    pub timestamp: u64,

    // S2S authentication fields
    /// Origin server domain (who sent this S2S request)
    #[serde(default)]
    pub origin_server: Option<String>,
    /// Hash of the ciphertext for integrity verification
    #[serde(default)]
    pub payload_hash: Option<String>,
    /// Ed25519 signature over the canonical envelope (base64)
    #[serde(default)]
    pub server_signature: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedMessageResponse {
    pub status: String,
    pub message_id: String,
}

/// Receive federated message from remote server
/// Served at: POST /federation/v1/messages
/// Helper function that accepts bytes directly (for Axum routes)
pub async fn receive_federated_message_bytes(
    ctx: &AppContext,
    body_bytes: bytes::Bytes,
) -> Result<hyper::Response<Full<Bytes>>, AppError> {
    receive_federated_message_http_impl(ctx, body_bytes).await
}

pub async fn receive_federated_message_http(
    ctx: &AppContext,
    body: IncomingBody,
) -> Result<hyper::Response<Full<Bytes>>, AppError> {
    // 1. Read request body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read request body");
            return Err(AppError::Validation(
                "Failed to read request body".to_string(),
            ));
        }
    };

    receive_federated_message_http_impl(ctx, body_bytes).await
}

/// Main implementation (extracted for reuse)
async fn receive_federated_message_http_impl(
    ctx: &AppContext,
    body_bytes: bytes::Bytes,
) -> Result<hyper::Response<Full<Bytes>>, AppError> {
    // 2. Parse JSON to FederatedMessageRequest
    let req: FederatedMessageRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid JSON in federated message request");
            return Err(AppError::Validation("Invalid JSON format".to_string()));
        }
    };

    // SECURITY: Hash user IDs for privacy in logs
    let salt = &ctx.config.logging.hash_salt;
    tracing::info!(
        message_id = %req.message_id,
        from_hash = %log_safe_id(&req.from, salt),
        to_hash = %log_safe_id(&req.to, salt),
        "Received federated message from remote server"
    );

    // 3. Validate sender is from their claimed domain
    let sender = match UserId::parse(&req.from) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, from_hash = %log_safe_id(&req.from, salt), "Invalid sender user ID");
            return Err(AppError::Validation("Invalid sender ID".to_string()));
        }
    };

    if !sender.is_federated() {
        tracing::warn!(from_hash = %log_safe_id(&req.from, salt), "Sender must be federated (must have @domain)");
        return Err(AppError::Validation("Sender must be federated".to_string()));
    }

    // 3.5 Verify server signature (if provided)
    // SECURITY: In production, signatures MUST be required
    if let (Some(origin_server), Some(payload_hash), Some(signature)) =
        (&req.origin_server, &req.payload_hash, &req.server_signature)
    {
        // SECURITY: Validate that origin_server matches sender's domain
        // Prevent envelope tampering by ensuring origin_server matches the sender's federated domain
        let sender_domain = sender.domain().unwrap_or_default();
        if *origin_server != sender_domain {
            tracing::warn!(
                message_id = %req.message_id,
                origin_server = %origin_server,
                sender_domain = %sender_domain,
                "origin_server mismatch: envelope claims different origin than sender's domain"
            );
            return Err(AppError::Validation(
                "origin_server does not match sender's domain".to_string(),
            ));
        }

        // Reconstruct envelope for verification
        let envelope = FederatedEnvelope {
            message_id: req.message_id.clone(),
            from: req.from.clone(),
            to: req.to.clone(),
            origin_server: origin_server.clone(),
            destination_server: ctx.config.instance_domain.clone(),
            timestamp: req.timestamp,
            payload_hash: payload_hash.clone(),
        };

        // Verify payload hash integrity (constant-time comparison to prevent timing attacks)
        let expected_hash = FederatedEnvelope::hash_payload(&req.ciphertext);
        use subtle::ConstantTimeEq;
        if !bool::from(expected_hash.as_bytes().ct_eq(payload_hash.as_bytes())) {
            tracing::warn!(
                message_id = %req.message_id,
                origin_server = %origin_server,
                "Payload hash mismatch - message may have been tampered"
            );
            return Err(AppError::Validation(
                "Payload integrity check failed".to_string(),
            ));
        }

        // Fetch origin server's public key and verify signature
        match ctx.public_key_cache.get_public_key(origin_server).await {
            Ok(public_key) => {
                match ServerSigner::verify_signature(&public_key, &envelope, signature) {
                    Ok(()) => {
                        tracing::debug!(
                            message_id = %req.message_id,
                            origin_server = %origin_server,
                            "S2S signature verified successfully"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            message_id = %req.message_id,
                            origin_server = %origin_server,
                            error = %e,
                            "S2S signature verification FAILED"
                        );
                        return Ok(json_response(
                            StatusCode::UNAUTHORIZED,
                            json!({"error": "Invalid server signature"}),
                        ));
                    }
                }
            }
            Err(e) => {
                // SECURITY: If federation is enabled, signature verification is mandatory
                // Cannot proceed without verifying the signature
                tracing::error!(
                    message_id = %req.message_id,
                    origin_server = %origin_server,
                    error = %e,
                    "Failed to fetch origin server's public key - cannot verify signature"
                );
                return Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({"error": "Cannot verify origin server: failed to fetch public key"}),
                ));
            }
        }
    } else if req.server_signature.is_some() {
        // Signature provided but missing required fields (origin_server or payload_hash)
        tracing::warn!(
            message_id = %req.message_id,
            "Incomplete signature data: missing origin_server or payload_hash"
        );
        return Err(AppError::Validation("Incomplete signature data: origin_server and payload_hash are required when server_signature is provided".to_string()));
    } else {
        // SECURITY: Server signature is REQUIRED for federated messages
        // This endpoint only accepts messages from remote federation servers
        tracing::warn!(
            message_id = %req.message_id,
            from_hash = %log_safe_id(&req.from, salt),
            "Received unsigned federated message - server signature is required"
        );
        return Err(AppError::Auth(
            "Server signature is required for federation messages".to_string(),
        ));
    }

    // 4. Validate recipient is local to this instance
    let recipient = match UserId::parse(&req.to) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, to_hash = %log_safe_id(&req.to, salt), "Invalid recipient user ID");
            return Err(AppError::Validation("Invalid recipient ID".to_string()));
        }
    };

    // Check if recipient is on this instance
    if recipient.is_federated() {
        // SECURITY: Handle case where domain() returns None (should not happen if is_federated() is true)
        let recipient_domain = recipient.domain().ok_or_else(|| {
            tracing::error!("Federated recipient has no domain (internal error)");
            AppError::Internal("Invalid recipient state".to_string())
        })?;

        if recipient_domain != ctx.config.instance_domain {
            tracing::warn!(
                recipient_domain = %recipient_domain,
                instance_domain = %ctx.config.instance_domain,
                "Recipient is not on this instance"
            );
            return Err(AppError::Validation(
                "Recipient not on this instance".to_string(),
            ));
        }
    }

    // 5. Convert to ChatMessage format (federated messages are always Regular encrypted)
    let chat_message = ChatMessage {
        id: req.message_id.clone(),
        from: req.from.clone(),
        to: req.to.clone(),
        message_type: construct_types::MessageType::Regular,
        ephemeral_public_key: Some(req.ephemeral_public_key),
        message_number: Some(req.message_number),
        content: Some(req.ciphertext),
        timestamp: req.timestamp,
    };

    // 6. Validate message structure
    if !chat_message.is_valid() {
        tracing::warn!(message_id = %req.message_id, "Invalid message structure");
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "Invalid message structure"}),
        ));
    }

    // 7. Phase 5: Write to Kafka first (source of truth)
    let envelope = KafkaMessageEnvelope::from(&chat_message);
    if let Some(kafka_producer) = &ctx.kafka_producer {
        if let Err(e) = kafka_producer.send_message(&envelope).await {
            tracing::error!(
                error = %e,
                message_id = %req.message_id,
                kafka_enabled = kafka_producer.is_enabled(),
                "Kafka write FAILED - federated message NOT persisted"
            );
            return Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Failed to persist message"}),
            ));
        }
    } else {
        tracing::error!(
            message_id = %req.message_id,
            "Kafka producer not available - federated message NOT persisted"
        );
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "Message persistence unavailable"}),
        ));
    }

    tracing::debug!(
        message_id = %req.message_id,
        "Federated message persisted to Kafka"
    );

    // Recipient offline - message already persisted to Kafka
    // delivery_worker will read from Kafka when recipient comes online
    // SECURITY: Hash user IDs for privacy
    tracing::info!(
        message_id = %req.message_id,
        from_hash = %log_safe_id(&req.from, salt),
        to_hash = %log_safe_id(&req.to, salt),
        "Federated message queued in Kafka for offline recipient"
    );

    Ok(json_response(
        StatusCode::OK,
        json!(FederatedMessageResponse {
            status: "queued".to_string(),
            message_id: req.message_id,
        }),
    ))
}
