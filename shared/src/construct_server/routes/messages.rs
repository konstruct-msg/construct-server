// ============================================================================
// Messages Routes (Double Ratchet Protocol)
// ============================================================================
//
// Endpoints:
// - POST /api/v1/messages - Send an E2E-encrypted message
// - GET /api/v1/messages - Get messages (long polling)
//
// See docs/PROTOCOL_SPECIFICATION.md for protocol details.
// ============================================================================

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// ============================================================================
// Response Padding for Traffic Analysis Protection
// ============================================================================
//
// All GET /messages responses are padded to fixed bucket sizes to prevent
// traffic analysis attacks that could reveal message count or content size.
//
// Buckets: 4KB, 16KB, 64KB, 256KB
// ============================================================================

/// Response size buckets in bytes (after JSON serialization)
const RESPONSE_BUCKETS: [usize; 4] = [
    4 * 1024,   // 4 KB - empty or few small messages
    16 * 1024,  // 16 KB - typical response
    64 * 1024,  // 64 KB - many messages
    256 * 1024, // 256 KB - maximum batch
];

/// Overhead for the _pad field in JSON: `,"_pad":"..."` = ~12 bytes + base64 content
const PAD_FIELD_OVERHEAD: usize = 12;

use crate::context::AppContext;
use crate::kafka::types::KafkaMessageEnvelope;
use crate::rate_limit::{RateLimitAction, is_user_in_warmup};
use crate::routes::extractors::TrustedUser;
use crate::utils::{extract_client_ip, log_safe_id};
use construct_crypto::{EncryptedMessage, ServerCryptoValidator};
use construct_error::AppError;
use construct_types::message::{ChatMessage, EndSessionData};

/// POST /api/v1/messages
/// Sends an E2E-encrypted message using Double Ratchet protocol
pub async fn send_message(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(sender_id): TrustedUser,
    headers: HeaderMap,
    Json(message): Json<EncryptedMessage>,
) -> Result<impl IntoResponse, AppError> {
    let sender_id_str = sender_id.to_string();

    // SECURITY: Check rate limiting BEFORE processing (DoS protection)
    {
        let mut queue = app_context.queue.lock().await;
        if let Ok(Some(reason)) = queue.is_user_blocked(&sender_id_str).await {
            drop(queue);
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                reason = %reason,
                "Blocked user attempted to send message"
            );
            return Err(AppError::Auth(format!(
                "Your account is temporarily blocked: {}",
                reason
            )));
        }

        // SECURITY: Check warmup-aware rate limits for new accounts (<48h)
        // This prevents spam from newly created accounts
        let in_warmup = is_user_in_warmup(&app_context.db_pool, sender_id)
            .await
            .unwrap_or(true); // Default to warmup (cautious)

        let action = RateLimitAction::SendMessageNew; // Use stricter limit for warmup
        let (max_count, window_seconds) = if in_warmup {
            action.warmup_limits() // 20 per hour for warmup
        } else {
            action.established_limits().unwrap_or((1000, 3600)) // 1000 per hour for established
        };

        if let Err(e) = queue
            .check_warmup_rate_limit(&sender_id_str, action.as_str(), max_count, window_seconds)
            .await
        {
            drop(queue);
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                in_warmup = in_warmup,
                max_count = max_count,
                error = %e,
                "Warmup rate limit exceeded for messages"
            );
            return Err(AppError::TooManyRequests(format!(
                "Rate limit exceeded: {}",
                e
            )));
        }

        // Check combined rate limit (user_id + IP) for authenticated operations
        // Extract IP from request headers
        let client_ip = extract_client_ip(&headers, None);

        // Use combined rate limiting if enabled (more precise)
        if app_context.config.security.combined_rate_limiting_enabled {
            match queue
                .increment_combined_rate_limit(&sender_id_str, &client_ip, 3600)
                .await
            {
                Ok(count) => {
                    let max_combined = app_context
                        .config
                        .security
                        .max_requests_per_user_ip_per_hour;
                    if count > max_combined {
                        drop(queue);
                        tracing::warn!(
                            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                            ip = %client_ip,
                            count = count,
                            limit = max_combined,
                            "Combined rate limit exceeded for messages"
                        );
                        return Err(AppError::Validation(format!(
                            "Rate limit exceeded: maximum {} messages per hour",
                            max_combined
                        )));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check combined rate limit");
                    // Fall through to user_id-only check
                }
            }
        }

        // Also check user_id-only rate limit (legacy, for backward compatibility)
        match queue.increment_message_count(&sender_id_str).await {
            Ok(count) => {
                let max_messages = app_context.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Message rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} messages per hour",
                        max_messages
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check message rate limit");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // SECURITY: Validate message size to prevent DoS
    if message.ciphertext.len() > construct_config::MAX_MESSAGE_SIZE {
        tracing::warn!(
            size = message.ciphertext.len(),
            limit = construct_config::MAX_MESSAGE_SIZE,
            sender_hash = %log_safe_id(&sender_id.to_string(), &app_context.config.logging.hash_salt),
            "Message ciphertext too large"
        );
        return Err(AppError::Validation(format!(
            "Message size exceeds maximum of {} bytes",
            construct_config::MAX_MESSAGE_SIZE
        )));
    }

    // Validate the message format
    let salt = &app_context.config.logging.hash_salt;
    if let Err(e) = ServerCryptoValidator::validate_encrypted_message_v3(&message) {
        tracing::warn!(
            error = %e,
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            "Message validation failed"
        );
        return Err(AppError::Validation(e.to_string()));
    }

    // Parse recipient_id
    let recipient_id = Uuid::parse_str(&message.recipient_id)
        .map_err(|_| AppError::Validation("Invalid recipient ID format".to_string()))?;

    // Security check: prevent sending to self
    if sender_id == recipient_id {
        return Err(AppError::Validation(
            "Cannot send message to self".to_string(),
        ));
    }

    // Create Kafka envelope for message
    let message_id = Uuid::new_v4().to_string();

    // SECURITY: Replay protection for messages
    // Use nonce from request or generate one, validate timestamp if provided
    let nonce = message.nonce.as_deref().unwrap_or(&message_id);
    let timestamp = message
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    // Validate timestamp if provided (5 minutes max age)
    const MAX_AGE_SECONDS: i64 = 300;
    let now = chrono::Utc::now().timestamp();
    if let Some(provided_timestamp) = message.timestamp {
        let age = now - provided_timestamp;
        if age > MAX_AGE_SECONDS {
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                timestamp = provided_timestamp,
                age_seconds = age,
                "Message timestamp too old - possible replay attack"
            );
            return Err(AppError::Validation(
                "Message timestamp is too old. Please send a new message.".to_string(),
            ));
        }
        if age < -60 {
            // Allow 60 seconds clock skew
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                timestamp = provided_timestamp,
                now = now,
                "Message timestamp too far in future"
            );
            return Err(AppError::Validation(
                "Message timestamp is too far in the future. Please check your clock.".to_string(),
            ));
        }
    }

    // Check replay protection using enhanced method
    {
        let mut queue = app_context.queue.lock().await;
        match queue
            .check_replay_with_timestamp(
                &message_id,
                &message.ciphertext,
                nonce,
                timestamp,
                MAX_AGE_SECONDS,
            )
            .await
        {
            Ok(true) => {
                // Message is new and valid
            }
            Ok(false) => {
                drop(queue);
                tracing::warn!(
                    sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                    message_id = %message_id,
                    "Replay attack detected for message"
                );
                return Err(AppError::Validation(
                    "This message was already sent or is a replay. Please generate a new message."
                        .to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check message replay protection");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Create Kafka envelope from EncryptedMessage using the standard conversion
    use crate::kafka::types::EncryptedMessageContext;
    let ctx = EncryptedMessageContext {
        sender_id: sender_id.to_string(),
        message_id: message_id.clone(),
    };
    let envelope = KafkaMessageEnvelope::from_encrypted_message(&message, &ctx);

    // ============================================================================
    // Week R2: 2-Phase Commit Protocol - Idempotent Message Delivery
    // ============================================================================
    //
    // Phase 1 (PREPARE): Check if temp_id exists, store PENDING, write to Kafka
    //   - If temp_id provided AND exists in Redis → Return existing message_id (idempotent)
    //   - If temp_id provided AND new → Store PENDING → Write Kafka → Return message_id
    //   - If no temp_id → Legacy mode (backward compatibility)
    //
    // Phase 2 (COMMIT): Client calls /messages/confirm with temp_id (separate endpoint)
    //
    // This prevents message loss when network fails after Kafka write but before
    // client receives 200 OK response.
    // ============================================================================

    // Generate or use provided temp_id for idempotency
    let temp_id = message
        .temp_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Phase 1: Check if this is a retry (temp_id already exists)
    if let Some(pending_storage) = &app_context.pending_message_storage {
        if let Ok(Some(existing)) = pending_storage.get_pending(&temp_id).await {
            // IDEMPOTENT: temp_id already exists, return existing message_id
            tracing::info!(
                temp_id = %temp_id,
                message_id = %existing.message_id,
                sender_hash = %log_safe_id(&sender_id.to_string(), salt),
                "Idempotent retry detected - returning existing message_id"
            );

            return Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "sent",
                    "messageId": existing.message_id,
                    "tempId": temp_id,
                    "idempotent": true
                })),
            ));
        }

        // Phase 1: Store PENDING state before Kafka write
        use crate::pending_messages::PendingMessageData;
        let pending_data = PendingMessageData::new(
            temp_id.clone(),
            message_id.clone(),
            sender_id.to_string(),
            recipient_id.to_string(),
        );

        if let Err(e) = pending_storage.store_pending(&pending_data).await {
            tracing::error!(
                error = %e,
                temp_id = %temp_id,
                message_id = %message_id,
                "Failed to store pending message - continuing without 2-phase commit"
            );
            // Continue without 2-phase commit (graceful degradation)
        } else {
            tracing::debug!(
                temp_id = %temp_id,
                message_id = %message_id,
                "Stored pending message (Phase 1)"
            );
        }
    }

    // Write to Kafka (Phase 5: source of truth) or directly to Redis (test mode)
    if let Some(kafka_producer) = &app_context.kafka_producer {
        // Production path: send to Kafka, delivery worker will write to Redis
        if kafka_producer.is_enabled() {
            match kafka_producer.send_message(&envelope).await {
                Ok((partition, offset)) => {
                    // Message sent successfully, update pending storage with Kafka info
                    if let Some(pending_storage) = &app_context.pending_message_storage
                        && let Err(e) = pending_storage
                            .update_kafka_info(&temp_id, partition, offset)
                            .await
                    {
                        tracing::warn!(
                            error = %e,
                            temp_id = %temp_id,
                            partition = partition,
                            offset = offset,
                            "Failed to update pending message with Kafka info"
                        );
                    }
                }
                Err(e) => {
                    use crate::kafka::CircuitBreakerError;

                    // Handle circuit breaker errors
                    let error_message = match &e {
                        CircuitBreakerError::Open(elapsed) => {
                            format!(
                                "Messaging service temporarily unavailable (circuit breaker open for {} seconds)",
                                elapsed.as_secs()
                            )
                        }
                        CircuitBreakerError::Timeout { timeout } => {
                            format!(
                                "Messaging service timeout (exceeded {} seconds)",
                                timeout.as_secs()
                            )
                        }
                        CircuitBreakerError::Inner(_) => {
                            "Messaging service unavailable".to_string()
                        }
                    };

                    // SECURITY: Use hashed IDs in error logs
                    tracing::error!(
                        error = %e,
                        sender_hash = %log_safe_id(&sender_id.to_string(), salt),
                        recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                        message_id = %message_id,
                        "Failed to send message to Kafka (circuit breaker)"
                    );

                    // Return 503 Service Unavailable
                    return Err(AppError::MessageQueue(error_message));
                }
            }
        } else {
            // Test mode: Kafka disabled, write directly to Redis
            tracing::info!(
                sender_hash = %log_safe_id(&sender_id.to_string(), salt),
                recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                message_id = %message_id,
                "Kafka disabled - writing message directly to Redis (test mode)"
            );

            // Write to recipient's Redis stream directly (bypassing Kafka)
            let mut queue = app_context.queue.lock().await;
            if let Err(e) = queue
                .write_message_to_user_stream(&recipient_id.to_string(), &envelope)
                .await
            {
                drop(queue);
                tracing::error!(
                    error = %e,
                    sender_hash = %log_safe_id(&sender_id.to_string(), salt),
                    recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                    message_id = %message_id,
                    "Failed to write message to Redis"
                );
                return Err(AppError::Internal(format!(
                    "Failed to deliver message: {}",
                    e
                )));
            }
            drop(queue);
        }
    } else {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
            message_id = %message_id,
            "Kafka producer not available - cannot send message"
        );
        return Err(AppError::Kafka("Kafka producer not available".to_string()));
    }

    // SECURITY: Use hashed IDs in success logs
    tracing::info!(
        sender_hash = %log_safe_id(&sender_id.to_string(), salt),
        recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
        message_id = %message_id,
        "Message sent successfully"
    );

    // Return success with proper status and camelCase field name
    // "sent" = message queued in Kafka, not yet delivered to recipient
    // "delivered" status comes later via delivery acknowledgment system
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "sent",
            "messageId": message_id,
            "tempId": temp_id
        })),
    ))
}

// ============================================================================
// Phase 2.5: REST API for Message Retrieval (Long Polling)
// ============================================================================

/// Validate Redis Stream ID format: {timestamp}-{sequence}
/// Examples: "0", "1707584371151-0", "1707584371151-42"
fn is_valid_stream_id(id: &str) -> bool {
    // Special IDs
    if id == "0" || id == "$" || id == "*" {
        return true;
    }

    // Check format: {timestamp}-{sequence}
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() != 2 {
        return false;
    }

    // Both parts must be valid numbers
    parts[0].parse::<u64>().is_ok() && parts[1].parse::<u64>().is_ok()
}

/// Query parameters for GET /api/v1/messages
#[derive(Debug, Deserialize)]
pub struct GetMessagesParams {
    /// Last Stream ID received - used for ACK-based pagination (optional)
    /// Format: "{timestamp}-{sequence}" (e.g., "1707584371151-5")
    /// On first request: omit this parameter
    /// On subsequent requests: use `nextSince` from previous response
    pub since: Option<String>,
    /// Timeout for long polling in seconds (default: 30, max: 60)
    pub timeout: Option<u64>,
    /// Maximum number of messages to return (default: 50, max: 100)
    pub limit: Option<u32>,
}

/// Message response structure for GET /api/v1/messages
/// ✅ FIXED: Aligned with API specification (specification.md)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")] // ✅ Use camelCase for all fields
pub struct MessageResponse {
    pub id: String, // Message UUID (unique identifier, NOT used for pagination)
    #[serde(skip_serializing)]
    pub stream_id: String, // Redis Stream ID (used for ACK-based pagination via nextSince)

    // ✅ SPEC: Use "from" and "to" as per specification.md (not sender_id/recipient_id)
    pub from: String,
    pub to: String,

    // Phase 4.5: Message type (Regular or EndSession)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>, // "DIRECT_MESSAGE" | "CONTROL_MESSAGE"

    // ✅ SPEC: Required fields for Double Ratchet protocol
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<String>, // Base64<Bytes>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    // ✅ SPEC: "content" field contains encrypted data (Base64<nonce || ciphertext_with_tag>)
    pub content: String,

    pub suite_id: u16, // ✅ Changed from u8 to u16 per spec, serialized as "suiteId"

    pub timestamp: u64, // ✅ Changed from i64 to u64 per spec

    // Legacy/internal fields (not in spec, skip if None)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<String>,
}

/// Response structure for GET /api/v1/messages
/// Includes optional padding field for traffic analysis protection
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")] // ✅ Use camelCase for all fields (nextSince, hasMore)
pub struct GetMessagesResponse {
    pub messages: Vec<MessageResponse>,
    /// Stream ID to use in next request for ACK-based pagination
    /// Format: "{timestamp}-{sequence}" (e.g., "1707584371151-5")
    /// Usage: GET /api/v1/messages?since=<this_value>
    /// Effect: Acknowledges receipt of all messages up to this ID (they will be deleted)
    /// 
    /// ✅ CRITICAL: This field is ALWAYS present (never skipped) to prevent client polling loops.
    /// When no messages, server returns the same 'since' value client sent, or "0-0" if none.
    pub next_since: Option<String>,
    pub has_more: bool,
    /// Random padding to normalize response sizes (traffic analysis protection)
    /// Clients should ignore this field
    #[serde(rename = "_pad", skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
}

impl GetMessagesResponse {
    /// Create a new response with automatic padding to the next bucket size
    pub fn new_padded(
        messages: Vec<MessageResponse>,
        next_since: Option<String>,
        has_more: bool,
    ) -> Self {
        let mut response = Self {
            messages,
            next_since,
            has_more,
            padding: None,
        };

        // Calculate current size without padding
        let current_size = serde_json::to_vec(&response).map(|v| v.len()).unwrap_or(0);

        // Find target bucket
        let target_bucket = RESPONSE_BUCKETS
            .iter()
            .find(|&&b| b >= current_size)
            .copied()
            .unwrap_or(RESPONSE_BUCKETS[RESPONSE_BUCKETS.len() - 1]);

        // Calculate padding needed
        // Account for the overhead of adding the _pad field itself
        if target_bucket > current_size + PAD_FIELD_OVERHEAD {
            let padding_bytes_needed = target_bucket - current_size - PAD_FIELD_OVERHEAD;
            // Base64 encoding: 3 bytes -> 4 chars, so we need ~75% of target bytes
            let raw_bytes_needed = (padding_bytes_needed * 3) / 4;

            if raw_bytes_needed > 0 {
                let random_bytes: Vec<u8> = (0..raw_bytes_needed)
                    .map(|_| rand::random::<u8>())
                    .collect();
                response.padding = Some(BASE64.encode(&random_bytes));
            }
        }

        response
    }
}

/// GET /api/v1/messages?since=<id>&timeout=30&limit=50
///
/// Long polling endpoint for retrieving messages.
///
/// Behavior:
/// 1. If there are new messages - returns them immediately
/// 2. If no new messages - waits up to `timeout` seconds (long polling)
/// 3. Returns messages when they arrive or empty array on timeout
///
/// Security:
/// - Requires JWT authentication (verified by Gateway, identity via X-User-Id header)
/// - Returns only messages for the authenticated user
/// - Rate limiting: configurable via MAX_LONG_POLL_REQUESTS_PER_WINDOW (default: 100/60s)
pub async fn get_messages(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
    Query(params): Query<GetMessagesParams>,
) -> Result<impl IntoResponse, AppError> {
    let user_id_str = user_id.to_string();
    let user_id_hash = log_safe_id(&user_id_str, &app_context.config.logging.hash_salt);

    // Track user as online for delivery_worker
    {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue
            .track_user_online(&user_id_str, &app_context.server_instance_id)
            .await
        {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to track user online status"
            );
        }

        // Publish notification that user came online
        if let Err(e) = queue
            .publish_user_online(
                &user_id_str,
                &app_context.server_instance_id,
                &app_context.config.online_channel,
            )
            .await
        {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to publish user online notification"
            );
        } else {
            tracing::debug!(
                user_hash = %user_id_hash,
                server_instance_id = %app_context.server_instance_id,
                channel = %app_context.config.online_channel,
                "Published user online notification"
            );
        }
    }

    // Rate limiting for long-polling (configurable via env vars)
    // Long-polling naturally limits itself (30-60s timeout), so we only need to prevent abuse
    // Default: 100 requests per 60 seconds - prevents spam but allows normal usage
    {
        let max_requests = app_context
            .config
            .security
            .max_long_poll_requests_per_window;
        let window_secs = app_context.config.security.long_poll_rate_limit_window_secs;

        let mut queue = app_context.queue.lock().await;
        let rate_limit_key = format!("rate:get_messages:{}", user_id_str);
        match queue
            .increment_rate_limit(&rate_limit_key, window_secs)
            .await
        {
            Ok(count) => {
                if count > max_requests as i64 {
                    drop(queue);
                    tracing::warn!(
                        user_hash = %user_id_hash,
                        count = count,
                        limit = max_requests,
                        window_secs = window_secs,
                        "Rate limit exceeded for get_messages"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} requests per {} seconds",
                        max_requests, window_secs
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit for get_messages");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Validate and set defaults for parameters
    let timeout = params.timeout.unwrap_or(30).min(60);
    let limit = params.limit.unwrap_or(50).min(100) as usize;

    // Step 1: Check for existing messages in Redis Streams
    // Pagination strategy: Use Redis Stream IDs for ACK-based delivery
    // - Client sends ?since=<stream_id> to acknowledge receipt
    // - Server deletes acknowledged messages and returns new ones
    // - This ensures exactly-once delivery
    let mut queue = app_context.queue.lock().await;
    let stream_messages = queue
        .read_user_messages_from_stream(
            &user_id_str,
            None,                    // server_instance_id not needed - using user-based streams
            params.since.as_deref(), // Stream ID for ACK (or None for first request)
            limit,
        )
        .await;

    let mut messages = match stream_messages {
        Ok(msgs) => {
            // Convert KafkaMessageEnvelope to MessageResponse
            let collected_messages = msgs
                .into_iter()
                .map(|(stream_id, envelope)| {
                    // Convert MessageType enum to string for API response
                    let message_type_str = match envelope.message_type {
                        crate::kafka::types::MessageType::DirectMessage => {
                            Some("DIRECT_MESSAGE".to_string())
                        }
                        crate::kafka::types::MessageType::ControlMessage => {
                            Some("CONTROL_MESSAGE".to_string())
                        }
                        crate::kafka::types::MessageType::MLSMessage => {
                            Some("MLS_MESSAGE".to_string())
                        }
                        crate::kafka::types::MessageType::MLSKeyPackage => {
                            Some("MLS_KEY_PACKAGE".to_string())
                        }
                        crate::kafka::types::MessageType::MLSWelcome => {
                            Some("MLS_WELCOME".to_string())
                        }
                        crate::kafka::types::MessageType::MLSCommit => {
                            Some("MLS_COMMIT".to_string())
                        }
                        crate::kafka::types::MessageType::MLSProposal => {
                            Some("MLS_PROPOSAL".to_string())
                        }
                        crate::kafka::types::MessageType::FederatedMessage => {
                            Some("FEDERATED_MESSAGE".to_string())
                        }
                    };

                    MessageResponse {
                        id: envelope.message_id.clone(),
                        stream_id: stream_id.clone(), // Internal use, skip in serialization
                        // ✅ SPEC: Use "from"/"to" as per specification
                        from: envelope.sender_id,
                        to: envelope.recipient_id,
                        // Phase 4.5: Include message type
                        message_type: message_type_str,
                        // ✅ SPEC: Include Double Ratchet fields
                        ephemeral_public_key: envelope.ephemeral_public_key,
                        message_number: envelope.message_number,
                        // ✅ SPEC: Use "content" field name
                        content: envelope.encrypted_payload,
                        timestamp: envelope.timestamp as u64,
                        suite_id: envelope.suite_id,
                        nonce: None, // Nonce is not stored in envelope
                        delivery_status: Some("delivered".to_string()), // Messages from stream are delivered
                    }
                })
                .collect::<Vec<_>>();

            if !collected_messages.is_empty() {
                tracing::info!(
                    user_hash = %user_id_hash,
                    count = collected_messages.len(),
                    last_stream_id = %collected_messages.last().map(|m| m.stream_id.as_str()).unwrap_or("NONE"),
                    "Successfully read {} messages from Redis stream for user",
                    collected_messages.len()
                );
            }

            collected_messages
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to read messages from stream"
            );
            vec![]
        }
    };

    // No client-side filtering needed - Redis XREAD already filters by stream ID
    // We get exactly the messages we need

    // If we have messages, return them immediately
    if !messages.is_empty() {
        drop(queue);
        // Return last Stream ID for next request (ACK-based pagination)
        // Client will send this back to acknowledge receipt and get next batch
        // ✅ CRITICAL FIX: ALWAYS return nextSince (never None)
        let next_since = Some(messages.last().map_or_else(
            || params.since.clone().unwrap_or_else(|| "0-0".to_string()),
            |m| {
                let stream_id = m.stream_id.trim();
                if stream_id.is_empty() {
                    tracing::error!(
                        user_hash = %user_id_hash,
                        message_id = %m.id,
                        "CRITICAL: Empty stream_id in message response - using fallback!"
                    );
                    // Fallback: use client's since or "0-0"
                    params.since.clone().unwrap_or_else(|| "0-0".to_string())
                } else {
                    stream_id.to_string()
                }
            }
        ));

        tracing::debug!(
            user_hash = %user_id_hash,
            count = messages.len(),
            next_since = ?next_since,
            "Returning {} messages immediately",
            messages.len()
        );

        return Ok((
            StatusCode::OK,
            Json(GetMessagesResponse::new_padded(
                messages, next_since, false, // TODO: Implement has_more logic
            )),
        ));
    }

    // No messages yet - proceed to long polling
    // Important: We should preserve the client's 'since' parameter for the final response
    // This allows client to maintain its position even when no new messages arrive

    tracing::debug!(
        user_hash = %user_id_hash,
        timeout = timeout,
        "No messages found, starting long polling"
    );

    // Wait for notification or timeout
    // NOTE: Do NOT hold the queue lock during sleep - it blocks all other requests!
    // wait_for_message_notification just sleeps, no Redis access needed
    let notification_received = {
        use tokio::time::Duration;
        tokio::time::sleep(Duration::from_secs(timeout)).await;
        false // Always return false - client will check for messages again
    };

    if notification_received {
        // Notification received - check for messages again
        let mut queue = app_context.queue.lock().await;
        let stream_messages = queue
            .read_user_messages_from_stream(
                &user_id_str,
                None, // server_instance_id not needed - using user-based streams
                params.since.as_deref(), // Stream ID for ACK
                limit,
            )
            .await;

        let new_messages = match stream_messages {
            Ok(msgs) => msgs
                .into_iter()
                .map(|(stream_id, envelope)| {
                    // Convert MessageType enum to string for API response
                    let message_type_str = match envelope.message_type {
                        crate::kafka::types::MessageType::DirectMessage => {
                            Some("DIRECT_MESSAGE".to_string())
                        }
                        crate::kafka::types::MessageType::ControlMessage => {
                            Some("CONTROL_MESSAGE".to_string())
                        }
                        crate::kafka::types::MessageType::MLSMessage => {
                            Some("MLS_MESSAGE".to_string())
                        }
                        crate::kafka::types::MessageType::MLSKeyPackage => {
                            Some("MLS_KEY_PACKAGE".to_string())
                        }
                        crate::kafka::types::MessageType::MLSWelcome => {
                            Some("MLS_WELCOME".to_string())
                        }
                        crate::kafka::types::MessageType::MLSCommit => {
                            Some("MLS_COMMIT".to_string())
                        }
                        crate::kafka::types::MessageType::MLSProposal => {
                            Some("MLS_PROPOSAL".to_string())
                        }
                        crate::kafka::types::MessageType::FederatedMessage => {
                            Some("FEDERATED_MESSAGE".to_string())
                        }
                    };

                    MessageResponse {
                        id: envelope.message_id.clone(),
                        stream_id: stream_id.clone(), // Internal use, skip in serialization
                        // ✅ SPEC: Use "from"/"to" as per specification
                        from: envelope.sender_id,
                        to: envelope.recipient_id,
                        // Phase 4.5: Include message type
                        message_type: message_type_str,
                        // ✅ SPEC: Include Double Ratchet fields
                        ephemeral_public_key: envelope.ephemeral_public_key,
                        message_number: envelope.message_number,
                        // ✅ SPEC: Use "content" field name
                        content: envelope.encrypted_payload,
                        timestamp: envelope.timestamp as u64,
                        suite_id: envelope.suite_id,
                        nonce: None,
                        delivery_status: Some("delivered".to_string()),
                    }
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_hash = %user_id_hash,
                    "Failed to read messages after notification"
                );
                vec![]
            }
        };

        if !new_messages.is_empty() {
            tracing::debug!(
                user_hash = %user_id_hash,
                count = new_messages.len(),
                last_stream_id = %new_messages.last().map(|m| m.stream_id.as_str()).unwrap_or("NONE"),
                "Read {} messages after notification",
                new_messages.len()
            );
        }

        // No filtering needed - Redis XREAD handles pagination
        messages = new_messages;
    }

    // Return Stream ID for ACK-based pagination
    // ✅ CRITICAL FIX: ALWAYS return nextSince to prevent infinite polling loop
    // 
    // Cases:
    // 1. Has messages → return last message's stream_id
    // 2. No messages + valid since → echo back client's since
    // 3. No messages + invalid/no since → return "0-0" (start of stream)
    let next_since = if !messages.is_empty() {
        // Case 1: Return last message's stream_id
        Some(messages.last().map_or_else(
            || params.since.clone().unwrap_or_else(|| "0-0".to_string()),
            |m| {
                let stream_id = m.stream_id.trim();
                if stream_id.is_empty() {
                    tracing::error!(
                        user_hash = %user_id_hash,
                        message_id = %m.id,
                        "CRITICAL: Empty stream_id in message response after long polling - using fallback!"
                    );
                    // Fallback: use client's since or "0-0"
                    params.since.clone().unwrap_or_else(|| "0-0".to_string())
                } else {
                    stream_id.to_string()
                }
            }
        ))
    } else {
        // Case 2 & 3: No messages - preserve client's position or start from beginning
        match params.since.as_ref() {
            Some(s) if is_valid_stream_id(s) => {
                // Valid since - echo it back so client keeps polling from same position
                Some(s.clone())
            }
            Some(s) => {
                // Invalid since - log warning and reset to start
                tracing::warn!(
                    user_hash = %user_id_hash,
                    invalid_since = %s,
                    "Client sent invalid 'since' parameter, resetting to '0-0'"
                );
                Some("0-0".to_string())
            }
            None => {
                // No since parameter - start from beginning
                Some("0-0".to_string())
            }
        }
    };

    tracing::debug!(
        user_hash = %user_id_hash,
        count = messages.len(),
        next_since = ?next_since,
        notification_received = notification_received,
        "Long polling completed"
    );

    Ok((
        StatusCode::OK,
        Json(GetMessagesResponse::new_padded(messages, next_since, false)),
    ))
}

// ============================================================================
// Phase 4.5: END_SESSION Control Messages
// ============================================================================

/// POST /api/v1/control
/// Sends a control message (e.g., END_SESSION) to notify recipient
pub async fn send_control_message(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(sender_id): TrustedUser,
    headers: HeaderMap,
    Json(data): Json<EndSessionData>,
) -> Result<impl IntoResponse, AppError> {
    let sender_id_str = sender_id.to_string();

    // SECURITY: Check rate limiting BEFORE processing (DoS protection)
    {
        let mut queue = app_context.queue.lock().await;
        if let Ok(Some(reason)) = queue.is_user_blocked(&sender_id_str).await {
            drop(queue);
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                reason = %reason,
                "Blocked user attempted to send control message"
            );
            return Err(AppError::Auth(format!(
                "Your account is temporarily blocked: {}",
                reason
            )));
        }

        // Check combined rate limit (user_id + IP) for authenticated operations
        let client_ip = extract_client_ip(&headers, None);

        // Use combined rate limiting if enabled
        if app_context.config.security.combined_rate_limiting_enabled {
            match queue
                .increment_combined_rate_limit(&sender_id_str, &client_ip, 3600)
                .await
            {
                Ok(count) => {
                    let max_combined = app_context
                        .config
                        .security
                        .max_requests_per_user_ip_per_hour;
                    if count > max_combined {
                        drop(queue);
                        tracing::warn!(
                            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                            ip = %client_ip,
                            count = count,
                            limit = max_combined,
                            "Combined rate limit exceeded for control messages"
                        );
                        return Err(AppError::Validation(format!(
                            "Rate limit exceeded: maximum {} requests per hour",
                            max_combined
                        )));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check combined rate limit");
                }
            }
        }

        // Also check user_id-only rate limit
        match queue.increment_message_count(&sender_id_str).await {
            Ok(count) => {
                let max_messages = app_context.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Control message rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} control messages per hour",
                        max_messages
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check control message rate limit");
            }
        }
        drop(queue);
    }

    // Parse recipient_id
    let recipient_id = Uuid::parse_str(&data.recipient_id)
        .map_err(|_| AppError::Validation("Invalid recipient ID format".to_string()))?;

    // Security check: prevent sending to self
    if sender_id == recipient_id {
        return Err(AppError::Validation(
            "Cannot send control message to self".to_string(),
        ));
    }

    // Check if recipient exists in database
    {
        let user_exists: Option<bool> =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)")
                .bind(recipient_id)
                .fetch_one(&*app_context.db_pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to check if recipient exists");
                    AppError::Database(e)
                })?;

        if !user_exists.unwrap_or(false) {
            return Err(AppError::Validation("Recipient does not exist".to_string()));
        }
    }

    // Create END_SESSION ChatMessage
    let chat_message =
        ChatMessage::new_end_session(sender_id_str.clone(), data.recipient_id.clone());

    let message_id = chat_message.id.clone();

    // Validate the control message
    if !chat_message.is_valid() {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
            "Failed to create valid END_SESSION message"
        );
        return Err(AppError::Internal(
            "Failed to create valid control message".to_string(),
        ));
    }

    // Convert to Kafka envelope (will automatically map to ControlMessage type)
    let envelope = KafkaMessageEnvelope::from(chat_message);

    // Write to Kafka (Phase 5: source of truth) or directly to Redis (test mode)
    let salt = &app_context.config.logging.hash_salt;
    if let Some(kafka_producer) = &app_context.kafka_producer {
        // Production path: send to Kafka, delivery worker will write to Redis
        if kafka_producer.is_enabled() {
            if let Err(e) = kafka_producer.send_message(&envelope).await {
                tracing::error!(
                    error = %e,
                    sender_hash = %log_safe_id(&sender_id_str, salt),
                    recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                    message_id = %message_id,
                    "Failed to send END_SESSION to Kafka"
                );
                return Err(AppError::Kafka(e.to_string()));
            }
        } else {
            // Test mode: Kafka disabled, write directly to Redis
            tracing::info!(
                sender_hash = %log_safe_id(&sender_id_str, salt),
                recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                message_id = %message_id,
                "Kafka disabled - writing END_SESSION directly to Redis (test mode)"
            );

            let mut queue = app_context.queue.lock().await;
            if let Err(e) = queue
                .write_message_to_user_stream(&recipient_id.to_string(), &envelope)
                .await
            {
                drop(queue);
                tracing::error!(
                    error = %e,
                    sender_hash = %log_safe_id(&sender_id_str, salt),
                    recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                    message_id = %message_id,
                    "Failed to write END_SESSION to Redis"
                );
                return Err(AppError::Internal(format!(
                    "Failed to deliver control message: {}",
                    e
                )));
            }
            drop(queue);
        }
    } else {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id_str, salt),
            recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
            message_id = %message_id,
            "Kafka producer not available - cannot send control message"
        );
        return Err(AppError::Kafka("Kafka producer not available".to_string()));
    }

    tracing::info!(
        sender_hash = %log_safe_id(&sender_id_str, salt),
        recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
        message_id = %message_id,
        reason = ?data.reason,
        "END_SESSION control message sent successfully"
    );

    // Return success with proper status and camelCase naming
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "sent",
            "messageId": message_id,
            "type": "END_SESSION"
        })),
    ))
}

// ============================================================================
// Week R2: 2-Phase Commit - Message Confirmation Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ConfirmMessageRequest {
    /// Temporary ID from Phase 1 (send_message response)
    #[serde(rename = "tempId")]
    pub temp_id: String,
}

/// POST /api/v1/messages/confirm - Phase 2 of 2-phase commit
///
/// Client calls this after successfully receiving message_id from send_message.
/// If network failed and client never received the response, they retry send_message
/// with the same temp_id (idempotent).
///
/// This endpoint is fire-and-forget - even if confirmation fails, the auto-cleanup
/// worker will confirm pending messages after 5 minutes.
pub async fn confirm_message(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(sender_id): TrustedUser,
    Json(data): Json<ConfirmMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let sender_id_str = sender_id.to_string();

    // Check if 2-phase commit is enabled
    let Some(pending_storage) = &app_context.pending_message_storage else {
        // 2-phase commit disabled, return success (backward compatibility)
        return Ok((
            StatusCode::OK,
            Json(json!({
                "status": "confirmed",
                "message": "2-phase commit not enabled"
            })),
        ));
    };

    // Confirm the pending message (Phase 2)
    match pending_storage.confirm_pending(&data.temp_id).await {
        Ok(true) => {
            tracing::debug!(
                temp_id = %data.temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Message confirmed (Phase 2)"
            );

            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "confirmed",
                    "tempId": data.temp_id
                })),
            ))
        }
        Ok(false) => {
            // temp_id not found (already confirmed or expired)
            tracing::warn!(
                temp_id = %data.temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Attempted to confirm non-existent pending message"
            );

            // Return success anyway (fire-and-forget, idempotent)
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "confirmed",
                    "tempId": data.temp_id,
                    "message": "Already confirmed or expired"
                })),
            ))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                temp_id = %data.temp_id,
                "Failed to confirm pending message"
            );

            // Return success anyway (fire-and-forget)
            // Auto-cleanup worker will confirm after 5 minutes
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "confirmed",
                    "tempId": data.temp_id,
                    "message": "Confirmation queued"
                })),
            ))
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_since_always_serialized() {
        // Test that nextSince field is always present in JSON (never omitted)
        
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct TestResponse {
            messages: Vec<String>,
            next_since: Option<String>,
        }
        
        // Case 1: Some(value) → "nextSince": "value"
        let response1 = TestResponse {
            messages: vec![],
            next_since: Some("1234567890-0".to_string()),
        };
        
        let json1 = serde_json::to_value(&response1).unwrap();
        assert!(json1.get("nextSince").is_some());
        assert_eq!(json1["nextSince"], "1234567890-0");
        
        // Case 2: None → "nextSince": null (field still present!)
        let response2 = TestResponse {
            messages: vec![],
            next_since: None,
        };
        
        let json2 = serde_json::to_value(&response2).unwrap();
        assert!(json2.get("nextSince").is_some(), "nextSince field must exist");
        assert!(json2["nextSince"].is_null());
    }

    #[test]
    fn test_is_valid_stream_id() {
        // Valid cases
        assert!(is_valid_stream_id("0"));
        assert!(is_valid_stream_id("$"));
        assert!(is_valid_stream_id("*"));
        assert!(is_valid_stream_id("1234567890-0"));
        assert!(is_valid_stream_id("1771079450941-0"));
        assert!(is_valid_stream_id("999999999999-42"));
        
        // Invalid cases
        assert!(!is_valid_stream_id(""));
        assert!(!is_valid_stream_id("not-a-number-0"));
        assert!(!is_valid_stream_id("1234567890"));  // Missing sequence
        assert!(!is_valid_stream_id("1234567890-"));
        assert!(!is_valid_stream_id("-0"));
        assert!(!is_valid_stream_id("abc-def"));
        assert!(!is_valid_stream_id("1234-5-6"));  // Too many parts
    }
}
