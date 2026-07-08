use std::sync::Arc;

use crate::context::MessagingServiceContext;
use crate::core;
use crate::spent_tag::{DeliveryTagStatus, check_and_mark_delivery_tag};
use construct_server_shared::shared::proto::services::v1 as proto;

/// Convert MessageEnvelope to proto Envelope
pub(crate) fn convert_envelope_to_proto(
    envelope: construct_server_shared::message::types::MessageEnvelope,
) -> anyhow::Result<construct_server_shared::shared::proto::core::v1::Envelope> {
    use base64::Engine;
    use construct_server_shared::message::types::MessageType;
    use construct_server_shared::shared::proto::core::v1 as core;

    // Sealed sender — reconstruct SealedSenderEnvelope, hide sender from proto.
    if envelope.is_sealed_sender {
        let sealed_inner_bytes = envelope
            .sealed_inner_b64
            .as_deref()
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .unwrap_or_default();

        return Ok(core::Envelope {
            sender: None, // anonymous — server does not know sender
            sender_device: None,
            recipient: Some(core::UserId {
                user_id: envelope.recipient_id,
                domain: None,
                display_name: None,
            }),
            recipient_device: None,
            content_type: core::ContentType::E2eeSignal.into(),
            message_id_type: Some(core::envelope::MessageIdType::MessageId(
                envelope.message_id,
            )),
            timestamp: envelope.timestamp,
            ttl: 0,
            priority: core::MessagePriority::Normal.into(),
            encrypted_payload: vec![],
            conversation_id: String::new(),
            server_metadata: None,
            client_metadata: None,
            forwarding_path: vec![],
            ephemeral_seconds: None,
            reactions: vec![],
            mentions: vec![],
            sealed_sender: Some(core::SealedSenderEnvelope {
                recipient_server: String::new(),
                sealed_inner: sealed_inner_bytes,
                forwarding_token: vec![],
                timestamp: 0,
            }),
        });
    }

    // Map Kafka MessageType → proto ContentType so clients can detect control messages
    // (SESSION_RESET, END_SESSION, KEY_SYNC) without trying to decrypt them.
    // If proto_content_type is set (new path), use it directly — preserves the exact
    // content_type the sender specified (e.g. SESSION_RESET_INIT=24, SENDER_SYNC=23).
    let content_type = if let Some(ct) = envelope.proto_content_type {
        core::ContentType::try_from(ct).unwrap_or(core::ContentType::E2eeSignal)
    } else {
        // Legacy fallback for envelopes without proto_content_type
        match envelope.message_type {
            MessageType::ControlMessage => match envelope.encrypted_payload.as_str() {
                "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
                "KEY_SYNC" => core::ContentType::KeySync,
                _ => core::ContentType::E2eeSignal,
            },
            _ => core::ContentType::E2eeSignal,
        }
    };

    // For control messages, send empty payload — the ASCII type string ("END_SESSION",
    // "SESSION_RESET") is NOT ciphertext and must not be passed to the decryption layer.
    let payload_bytes = match content_type {
        core::ContentType::SessionReset | core::ContentType::KeySync => vec![],
        _ => base64::engine::general_purpose::STANDARD
            .decode(&envelope.encrypted_payload)
            .unwrap_or_else(|_| envelope.encrypted_payload.into_bytes()),
    };

    Ok(core::Envelope {
        sender: Some(core::UserId {
            user_id: envelope.sender_id,
            domain: None,
            display_name: None,
        }),
        sender_device: None,
        recipient: Some(core::UserId {
            user_id: envelope.recipient_id,
            domain: None,
            display_name: None,
        }),
        recipient_device: None,
        content_type: content_type.into(),
        message_id_type: Some(core::envelope::MessageIdType::MessageId(
            envelope.message_id,
        )),
        timestamp: envelope.timestamp,
        ttl: 0,
        priority: core::MessagePriority::Normal.into(),
        encrypted_payload: payload_bytes,
        // conversation_id is intentionally empty: it is server-visible metadata
        // and must not carry E2E semantics. See envelope.proto for details.
        conversation_id: String::new(),
        server_metadata: None,
        client_metadata: None,
        forwarding_path: vec![],
        ephemeral_seconds: None,
        reactions: vec![],
        mentions: vec![],
        sealed_sender: None,
    })
}

/// Route a SealedSenderEnvelope:
///  - Cross-server (recipient_server ≠ ours): forward via FederationClient
///  - Local (same server or empty): parse SealedInner → deliver to recipient_user_id
pub(crate) async fn dispatch_sealed_sender(
    context: &Arc<MessagingServiceContext>,
    sealed: &construct_server_shared::shared::proto::core::v1::SealedSenderEnvelope,
) -> anyhow::Result<proto::SendMessageResponse> {
    use construct_server_shared::federation::FederationClient;
    use construct_server_shared::message::types::MessageEnvelope;
    use construct_server_shared::shared::proto::core::v1 as proto_core;
    use prost::Message;

    let our_domain = &context.config.federation.instance_domain;
    let message_id = uuid::Uuid::new_v4().to_string();

    // Cross-server: forward sealed_inner opaquely to recipient server
    if !sealed.recipient_server.is_empty() && sealed.recipient_server != *our_domain {
        let target = &sealed.recipient_server;
        let client = match &context.server_signer {
            Some(signer) => FederationClient::new_with_signer(signer.clone(), our_domain.clone()),
            None => FederationClient::new(),
        };

        client
            .send_sealed_message(target, &message_id, &sealed.sealed_inner, sealed.timestamp)
            .await
            .map_err(|e| anyhow::anyhow!("Sealed sender federation failed to {}: {}", target, e))?;

        return Ok(proto::SendMessageResponse {
            message_id,
            message_number: 0,
            server_timestamp: chrono::Utc::now().timestamp_millis(),
            success: true,
            error: None,
            rate_limit_challenge: None,
            attempt_id: None,
        });
    }

    // Local delivery: decode SealedInner to get recipient_user_id
    let sealed_inner = proto_core::SealedInner::decode(sealed.sealed_inner.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decode SealedInner: {}", e))?;

    let recipient_id = sealed_inner.recipient_user_id.clone();
    if recipient_id.is_empty() {
        anyhow::bail!("SealedInner.recipient_user_id is required");
    }

    // ── Privacy Pass token redemption (stealth-sealed-sender-v2 Phase 1) ───
    // Gate cheapest-first, before the delivery-tag check and dispatch. See
    // construct-docs/decisions/stealth-sealed-sender-v2-always-on.md §3 Phase 1.
    use construct_config::StealthTokenPolicy;
    let policy = context.config.messaging.stealth_token_policy;
    if policy != StealthTokenPolicy::Off {
        let mode_label = match policy {
            StealthTokenPolicy::Warn => "warn",
            StealthTokenPolicy::Enforce => "enforce",
            StealthTokenPolicy::Off => unreachable!(),
        };

        construct_metrics::STEALTH_SEALED_LOCAL_TOTAL.inc();
        let has_token =
            !sealed_inner.token_nonce.is_empty() && !sealed_inner.token_bytes.is_empty();
        construct_metrics::STEALTH_TOKEN_PRESENT_TOTAL
            .with_label_values(&[if has_token { "present" } else { "absent" }])
            .inc();

        let mut conn = context.redis_conn.clone();
        let result = crate::token_redeem::redeem_token_checked(
            &mut conn,
            context.token_issuer_key.as_ref(),
            context.token_enc_static_secret.as_ref(),
            &sealed_inner.token_nonce,
            &sealed_inner.token_bytes,
        )
        .await;

        let result_label = result.as_label();
        construct_metrics::STEALTH_TOKEN_CHECK_TOTAL
            .with_label_values(&[mode_label, result_label])
            .inc();

        if result != crate::token_redeem::TokenRedeemResult::Ok {
            if policy == StealthTokenPolicy::Enforce {
                tracing::warn!(
                    result = result_label,
                    "sealed sender: Privacy Pass token redemption failed — rejecting (enforce mode)"
                );
                anyhow::bail!("privacy pass token redemption failed: {}", result_label);
            } else {
                tracing::info!(
                    result = result_label,
                    "sealed sender: Privacy Pass token redemption failed — allowing (warn mode)"
                );
            }
        }
    }

    // ── Delivery-tag anti-replay (two-layer) ───────────────────────────────
    // SealedInner.delivery_tag is a per-message random nonce (32 bytes).
    // We check it against:
    //   • exact cache (5 min)  — no false positives, catches recent replays
    //   • seen cache  (24 h)   — long-term dedup (exact keys, not probabilistic)
    //
    // If the tag was already seen we return success without re-delivering —
    // this is intentional: legitimate retries get an idempotent "OK" and
    // replay attackers learn nothing (same response either way).
    //
    // Fail-open on Redis error so a Redis outage cannot silently drop messages.
    if !sealed_inner.delivery_tag.is_empty() {
        let mut conn = context.redis_conn.clone();
        match check_and_mark_delivery_tag(&mut conn, &sealed_inner.delivery_tag).await {
            Ok(DeliveryTagStatus::New) => {
                // First time we see this tag — proceed to delivery.
            }
            Ok(status) => {
                tracing::warn!(
                    tag_prefix = %hex::encode(&sealed_inner.delivery_tag[..4.min(sealed_inner.delivery_tag.len())]),
                    status = ?status,
                    "sealed sender: delivery_tag replay — dropping silently"
                );
                return Ok(proto::SendMessageResponse {
                    message_id: uuid::Uuid::new_v4().to_string(),
                    message_number: 0,
                    server_timestamp: chrono::Utc::now().timestamp_millis(),
                    success: true,
                    error: None,
                    rate_limit_challenge: None,
                    attempt_id: None,
                });
            }
            Err(e) => {
                // Fail-open: Redis unavailable → deliver the message, log the error.
                tracing::error!(
                    error = %e,
                    "delivery_tag cache unavailable — delivering without replay check"
                );
            }
        }
    }

    let msg_envelope = MessageEnvelope::from_sealed_sender(
        message_id.clone(),
        recipient_id,
        sealed.sealed_inner.to_vec(),
    );

    let app_context = Arc::new(context.to_app_context());
    core::dispatch_envelope(
        &app_context,
        msg_envelope,
        context.notification_context.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(proto::SendMessageResponse {
        message_id,
        message_number: 0,
        server_timestamp: chrono::Utc::now().timestamp_millis(),
        success: true,
        error: None,
        rate_limit_challenge: None,
        attempt_id: None,
    })
}
