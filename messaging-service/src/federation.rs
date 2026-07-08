use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use base64::Engine as _;
use construct_federation::{FederatedEnvelope, PublicKeyCache, ServerSigner};
use construct_rate_limit::sliding_window_check_and_record;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::context::MessagingServiceContext;
use crate::envelope::dispatch_sealed_sender;

// ── Request / Response types ──────────────────────────────────────────────

/// Inbound federated sealed sender request (matches outbound FederatedSealedRequest format).
/// Thin JSON parsing layer — converts to internal SealedSenderEnvelope proto.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InboundSealedRequest {
    pub(crate) message_id: String,
    /// Base64-encoded serialized SealedInner proto
    pub(crate) sealed_inner: String,
    /// Origin server domain (who signed and sent this)
    pub(crate) origin_server: String,
    pub(crate) timestamp: u64,
    /// SHA-256 hash of base64(sealed_inner)
    pub(crate) payload_hash: String,
    /// Ed25519 signature over canonical FederatedEnvelope (base64)
    pub(crate) server_signature: Option<String>,
}

/// Inbound federated message request (regular, non-sealed).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InboundMessageRequest {
    pub(crate) message_id: String,
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) ciphertext: String,
    pub(crate) origin_server: String,
    pub(crate) timestamp: u64,
    pub(crate) payload_hash: String,
    pub(crate) server_signature: Option<String>,
}

/// S2S response sent back to the origin server.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FederationResponse {
    pub(crate) status: String,
    pub(crate) message_id: String,
}

// ── Rate limiting helper ──────────────────────────────────────────────────

/// Check per-origin sliding window rate limit.
/// Returns `Ok(())` if allowed, `Err(429)` if exceeded.
async fn check_origin_rate_limit(
    context: &MessagingServiceContext,
    origin_server: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let max_per_hour = context.config.federation.max_requests_per_origin_per_hour;
    if max_per_hour <= 0 {
        return Ok(());
    }

    let mut conn = context.redis_conn.clone();
    let key = format!("rl:federation:origin:{}", origin_server);
    match sliding_window_check_and_record(&mut conn, &key, max_per_hour as u32, 3600).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!(origin = %origin_server, limit = max_per_hour, "Per-origin rate limit exceeded");
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "rate limit exceeded"})),
            ))
        }
        Err(e) => {
            // Fail-open on Redis error — don't block messages due to rate limiter outage
            tracing::warn!(origin = %origin_server, error = %e, "Rate limit check failed (fail-open)");
            Ok(())
        }
    }
}

// ── Sealed sender handler ─────────────────────────────────────────────────

/// POST /federation/v1/sealed
///
/// Receives a sealed-sender message forwarded from another federation node.
/// Verifies the origin server's Ed25519 signature, then dispatches the sealed
/// inner payload to the local delivery pipeline (recipient is inside SealedInner).
pub(crate) async fn handle_inbound_sealed(
    State(context): State<Arc<MessagingServiceContext>>,
    Json(req): Json<InboundSealedRequest>,
) -> Result<(StatusCode, Json<FederationResponse>), (StatusCode, Json<serde_json::Value>)> {
    if !context.config.federation.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "federation not enabled"})),
        ));
    }

    // ── Per-origin rate limit ────────────────────────────────────────────
    check_origin_rate_limit(&context, &req.origin_server).await?;

    // ── Payload hash integrity check ─────────────────────────────────────
    let expected_hash = FederatedEnvelope::hash_payload(&req.sealed_inner);
    if expected_hash != req.payload_hash {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "payload hash mismatch"})),
        ));
    }

    // ── Signature verification ───────────────────────────────────────────
    if let Some(sig) = &req.server_signature {
        let cache = PublicKeyCache::new();
        match cache.get_public_key(&req.origin_server).await {
            Ok(remote_pk) => {
                let envelope = FederatedEnvelope {
                    message_id: req.message_id.clone(),
                    from: String::new(),
                    to: String::new(),
                    origin_server: req.origin_server.clone(),
                    destination_server: context.config.federation.instance_domain.clone(),
                    timestamp: req.timestamp,
                    payload_hash: req.payload_hash.clone(),
                };
                if ServerSigner::verify_signature(&remote_pk, &envelope, sig).is_err() {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid server signature"})),
                    ));
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(
                        serde_json::json!({"error": format!("failed to fetch origin public key: {}", e)}),
                    ),
                ));
            }
        }
    } else if context.config.federation.mtls.required {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({"error": "signature required when FEDERATION_MTLS_REQUIRED=true"}),
            ),
        ));
    }

    // ── Decode sealed_inner and dispatch ─────────────────────────────────
    let sealed_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.sealed_inner) {
        Ok(b) => b,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid base64 in sealed_inner"})),
            ));
        }
    };

    use construct_server_shared::shared::proto::core::v1 as proto_core;
    let sealed_envelope = proto_core::SealedSenderEnvelope {
        recipient_server: String::new(),
        sealed_inner: sealed_bytes,
        forwarding_token: vec![],
        timestamp: req.timestamp as i64,
    };

    match dispatch_sealed_sender(&context, &sealed_envelope).await {
        Ok(response) => {
            info!(
                message_id = %response.message_id,
                origin = %req.origin_server,
                "Inbound sealed sender message delivered locally"
            );
            Ok((
                StatusCode::OK,
                Json(FederationResponse {
                    status: "accepted".to_string(),
                    message_id: response.message_id,
                }),
            ))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                origin = %req.origin_server,
                "Inbound sealed sender dispatch failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("delivery failed: {}", e)})),
            ))
        }
    }
}

// ── Regular message handler ───────────────────────────────────────────────

/// POST /federation/v1/messages
///
/// Receives a signed regular (non-sealed) message from another federation node.
/// Verifies the origin server's Ed25519 signature, then dispatches to local delivery.
pub(crate) async fn handle_inbound_message(
    State(context): State<Arc<MessagingServiceContext>>,
    Json(req): Json<InboundMessageRequest>,
) -> Result<(StatusCode, Json<FederationResponse>), (StatusCode, Json<serde_json::Value>)> {
    if !context.config.federation.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "federation not enabled"})),
        ));
    }

    // ── Per-origin rate limit ────────────────────────────────────────────
    check_origin_rate_limit(&context, &req.origin_server).await?;

    // ── Payload hash integrity check ─────────────────────────────────────
    let expected_hash = FederatedEnvelope::hash_payload(&req.ciphertext);
    if expected_hash != req.payload_hash {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "payload hash mismatch"})),
        ));
    }

    // ── Signature verification ───────────────────────────────────────────
    if let Some(sig) = &req.server_signature {
        let cache = PublicKeyCache::new();
        match cache.get_public_key(&req.origin_server).await {
            Ok(remote_pk) => {
                let envelope = FederatedEnvelope {
                    message_id: req.message_id.clone(),
                    from: req.from.clone(),
                    to: req.to.clone(),
                    origin_server: req.origin_server.clone(),
                    destination_server: context.config.federation.instance_domain.clone(),
                    timestamp: req.timestamp,
                    payload_hash: req.payload_hash.clone(),
                };
                if ServerSigner::verify_signature(&remote_pk, &envelope, sig).is_err() {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid server signature"})),
                    ));
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(
                        serde_json::json!({"error": format!("failed to fetch origin public key: {}", e)}),
                    ),
                ));
            }
        }
    } else if context.config.federation.mtls.required {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({"error": "signature required when FEDERATION_MTLS_REQUIRED=true"}),
            ),
        ));
    }

    // ── Build MessageEnvelope and dispatch ───────────────────────────────
    use construct_server_shared::message::types::MessageEnvelope;
    use construct_server_shared::message::types::MessageType;

    let envelope = MessageEnvelope {
        message_id: req.message_id.clone(),
        sender_id: req.from.clone(),
        recipient_id: req.to.clone(),
        timestamp: req.timestamp as i64,
        message_type: MessageType::DirectMessage,
        encrypted_payload: req.ciphertext.clone(),
        content_hash: req.payload_hash.clone(),
        origin_server: Some(req.origin_server.clone()),
        federated: true,
        server_signature: req.server_signature.clone(),
        is_sealed_sender: false,
        sealed_inner_b64: None,
        ephemeral_public_key: None,
        message_number: None,
        mls_payload: None,
        group_id: None,
        crypto_suite_id: 0,
        max_queue_len: None,
        proto_content_type: None,
    };

    let app_context = Arc::new(context.to_app_context());
    match crate::core::dispatch_envelope(
        &app_context,
        envelope,
        context.notification_context.clone(),
    )
    .await
    {
        Ok(()) => {
            info!(
                message_id = %req.message_id,
                from = %req.from,
                to = %req.to,
                origin = %req.origin_server,
                "Inbound federated message delivered locally"
            );
            Ok((
                StatusCode::OK,
                Json(FederationResponse {
                    status: "accepted".to_string(),
                    message_id: req.message_id,
                }),
            ))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                message_id = %req.message_id,
                "Inbound federated message dispatch failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("delivery failed: {}", e)})),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_inbound_sealed_request_deserialize() {
        let json_str = json!({
            "messageId": "msg-123",
            "sealedInner": "dGhpcyBpcyBzZWFsZWQgZGF0YQ==",
            "originServer": "server-a.com",
            "timestamp": 1700000000,
            "payloadHash": "abc123hash",
            "serverSignature": "sig123"
        })
        .to_string();

        let req: InboundSealedRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(req.message_id, "msg-123");
        assert_eq!(req.origin_server, "server-a.com");
        assert_eq!(req.timestamp, 1700000000);
        assert_eq!(req.payload_hash, "abc123hash");
        assert_eq!(req.server_signature, Some("sig123".to_string()));
        assert_eq!(req.sealed_inner, "dGhpcyBpcyBzZWFsZWQgZGF0YQ==");
    }

    #[test]
    fn test_inbound_sealed_request_no_signature() {
        let json_str = json!({
            "messageId": "msg-456",
            "sealedInner": "dGVzdA==",
            "originServer": "server-b.com",
            "timestamp": 1700000001,
            "payloadHash": "def456hash"
        })
        .to_string();

        let req: InboundSealedRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(req.message_id, "msg-456");
        assert!(req.server_signature.is_none());
    }

    #[test]
    fn test_inbound_message_request_deserialize() {
        let json_str = json!({
            "messageId": "msg-789",
            "from": "alice@server-a.com",
            "to": "bob@server-b.com",
            "ciphertext": "ZW5jcnlwdGVk",
            "originServer": "server-a.com",
            "timestamp": 1700000002,
            "payloadHash": "ghi789hash",
            "serverSignature": "sig456"
        })
        .to_string();

        let req: InboundMessageRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(req.message_id, "msg-789");
        assert_eq!(req.from, "alice@server-a.com");
        assert_eq!(req.to, "bob@server-b.com");
        assert_eq!(req.ciphertext, "ZW5jcnlwdGVk");
        assert_eq!(req.server_signature, Some("sig456".to_string()));
    }

    #[test]
    fn test_federated_envelope_sealed_round_trip() {
        let seed_b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let signer =
            ServerSigner::from_seed_base64(seed_b64, "origin.konstruct.cc".to_string()).unwrap();

        let sealed_inner_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"fake-sealed-inner");
        let payload_hash = FederatedEnvelope::hash_payload(&sealed_inner_b64);
        let envelope = FederatedEnvelope {
            message_id: "test-sealed-001".to_string(),
            from: String::new(),
            to: String::new(),
            origin_server: "origin.konstruct.cc".to_string(),
            destination_server: "dest.konstruct.cc".to_string(),
            timestamp: 1704067200,
            payload_hash: payload_hash.clone(),
        };

        let signature = signer.sign_message(&envelope);
        let public_key = signer.public_key_base64();

        let verify_envelope = FederatedEnvelope {
            message_id: "test-sealed-001".to_string(),
            from: String::new(),
            to: String::new(),
            origin_server: "origin.konstruct.cc".to_string(),
            destination_server: "dest.konstruct.cc".to_string(),
            timestamp: 1704067200,
            payload_hash,
        };

        let result = ServerSigner::verify_signature(&public_key, &verify_envelope, &signature);
        assert!(result.is_ok(), "Signature should verify correctly");
    }

    #[test]
    fn test_federated_envelope_message_round_trip() {
        let seed_b64 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
        let signer =
            ServerSigner::from_seed_base64(seed_b64, "origin.konstruct.cc".to_string()).unwrap();

        let payload_hash = FederatedEnvelope::hash_payload("encrypted-content");
        let envelope = FederatedEnvelope {
            message_id: "msg-regular-001".to_string(),
            from: "alice@origin.konstruct.cc".to_string(),
            to: "bob@dest.konstruct.cc".to_string(),
            origin_server: "origin.konstruct.cc".to_string(),
            destination_server: "dest.konstruct.cc".to_string(),
            timestamp: 1704067200,
            payload_hash: payload_hash.clone(),
        };

        let signature = signer.sign_message(&envelope);
        let public_key = signer.public_key_base64();

        let result = ServerSigner::verify_signature(&public_key, &envelope, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_payload_hash_integrity() {
        let hash1 = FederatedEnvelope::hash_payload("same-content");
        let hash2 = FederatedEnvelope::hash_payload("same-content");
        assert_eq!(hash1, hash2);

        let hash3 = FederatedEnvelope::hash_payload("different-content");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_federation_response_serialize() {
        let resp = FederationResponse {
            status: "accepted".to_string(),
            message_id: "msg-001".to_string(),
        };

        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["status"], "accepted");
        assert_eq!(parsed["messageId"], "msg-001");
    }
}
