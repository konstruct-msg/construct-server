use std::sync::Arc;

use crate::context::MessagingServiceContext;
use crate::core;
use construct_server_shared::shared::proto::services::v1 as proto;

/// Convert KafkaMessageEnvelope to proto Envelope
pub(crate) fn convert_kafka_envelope_to_proto(
    envelope: construct_server_shared::kafka::types::KafkaMessageEnvelope,
) -> anyhow::Result<construct_server_shared::shared::proto::core::v1::Envelope> {
    use base64::Engine;
    use construct_server_shared::kafka::types::MessageType;
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
            reply_to_message_id: None,
            edits_message_id: None,
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
    let content_type = match envelope.message_type {
        MessageType::ControlMessage => match envelope.encrypted_payload.as_str() {
            "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
            "KEY_SYNC" => core::ContentType::KeySync,
            _ => core::ContentType::E2eeSignal,
        },
        _ => core::ContentType::E2eeSignal,
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
        conversation_id: String::new(),
        server_metadata: None,
        client_metadata: None,
        forwarding_path: vec![],
        ephemeral_seconds: None,
        reply_to_message_id: None,
        edits_message_id: envelope.edits_message_id,
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
    use construct_server_shared::kafka::types::KafkaMessageEnvelope;
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
        });
    }

    // Local delivery: decode SealedInner to get recipient_user_id
    let sealed_inner = proto_core::SealedInner::decode(sealed.sealed_inner.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decode SealedInner: {}", e))?;

    let recipient_id = sealed_inner.recipient_user_id.clone();
    if recipient_id.is_empty() {
        anyhow::bail!("SealedInner.recipient_user_id is required");
    }

    let kafka_envelope = KafkaMessageEnvelope::from_sealed_sender(
        message_id.clone(),
        recipient_id,
        sealed.sealed_inner.to_vec(),
    );

    let app_context = Arc::new(context.to_app_context());
    core::dispatch_envelope(&app_context, kafka_envelope)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(proto::SendMessageResponse {
        message_id,
        message_number: 0,
        server_timestamp: chrono::Utc::now().timestamp_millis(),
        success: true,
        error: None,
        rate_limit_challenge: None,
    })
}
