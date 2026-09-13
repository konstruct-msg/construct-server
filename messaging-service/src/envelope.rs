use std::sync::Arc;

use crate::context::MessagingServiceContext;
use crate::core;
use crate::spent_tag::{DeliveryTagStatus, check_and_mark_delivery_tag, unmark_delivery_tag};
use construct_server_shared::shared::proto::services::v1 as proto;

/// Privacy Pass redemption rejected under `enforce` mode.
///
/// Carried as a typed error inside `anyhow::Error` so RPC handlers can downcast and
/// map it to `FAILED_PRECONDITION` with the stable message `privacy_pass:{label}`
/// instead of a blanket internal error. Clients key off that prefix to force a wallet
/// replenish and retry the sealed send once — and must NEVER downgrade to an
/// identified send (otherwise the server could deanonymize a sender on demand by
/// rejecting its tokens). See construct-docs
/// decisions/sealed-sender-anti-abuse-economics.md.
#[derive(Debug)]
pub(crate) struct TokenRejected {
    pub(crate) label: &'static str,
}

impl std::fmt::Display for TokenRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "privacy_pass:{}", self.label)
    }
}

impl std::error::Error for TokenRejected {}

/// Convert MessageEnvelope to proto Envelope
pub(crate) fn convert_envelope_to_proto(
    envelope: construct_server_shared::message::types::MessageEnvelope,
) -> anyhow::Result<construct_server_shared::shared::proto::core::v1::Envelope> {
    use construct_server_shared::message::types::MessageType;
    use construct_server_shared::shared::proto::core::v1 as core;

    // Sealed sender — reconstruct SealedSenderEnvelope, hide sender from proto.
    if envelope.is_sealed_sender {
        let sealed_inner_bytes = envelope.sealed_inner.unwrap_or_default();

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

    // Map MessageType → proto ContentType so clients can detect control messages
    // (SESSION_RESET, END_SESSION, KEY_SYNC) without trying to decrypt them.
    // If proto_content_type is set (new path), use it directly — preserves the exact
    // content_type the sender specified (e.g. SESSION_RESET_INIT=24, SENDER_SYNC=23).
    let content_type = if let Some(ct) = envelope.proto_content_type {
        core::ContentType::try_from(ct).unwrap_or(core::ContentType::E2eeSignal)
    } else {
        // Legacy fallback for envelopes without proto_content_type
        match envelope.message_type {
            MessageType::ControlMessage => {
                match std::str::from_utf8(&envelope.encrypted_payload).unwrap_or("") {
                    "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
                    "KEY_SYNC" => core::ContentType::KeySync,
                    _ => core::ContentType::E2eeSignal,
                }
            }
            _ => core::ContentType::E2eeSignal,
        }
    };

    // For control messages, send empty payload — the ASCII type label is NOT
    // ciphertext and must not be passed to the decryption layer.
    // E2EE path: encrypted_payload is already raw ciphertext bytes (dual-deser
    // normalized legacy base64 strings on read).
    let payload_bytes = match content_type {
        core::ContentType::SessionReset | core::ContentType::KeySync => vec![],
        _ => envelope.encrypted_payload,
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

/// What the token gate does about one redemption outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenGateAction {
    /// The envelope proceeds and the outcome is what the policy expects.
    Deliver,
    /// The envelope is refused; the client replenishes and retries once.
    Reject,
    /// The envelope proceeds because the gate could not run at all. Distinct from
    /// `Deliver` so the skip is metered rather than looking like an ordinary pass.
    DeliverUnchecked,
}

/// Decide what `policy` does about `result`.
///
/// ── "Cannot check" is not "invalid" ─────────────────────────────────────────────
/// The spent-nonce set lives in Redis, and Redis is one container. Until 2026-09-13
/// `RedisError` took the same branch as a forged token, so a Redis outage refused every
/// sealed send — which is all ordinary messaging, because `StealthSendRecovery` forbids
/// falling back to an identified send and is right to: a server that can force identified
/// sends by rejecting tokens can deanonymise any sender on demand.
///
/// It was worse than an outage. Each rejection makes the client call
/// `BlindTokenService.forceReplenish()`, which clears both back-off timers and fetches a
/// new batch, so a degraded backend answered every failed send with extra load on the
/// issuer path. And it handed anyone who could degrade Redis a way to stop delivery
/// entirely, which is a larger prize than anything the token gate protects.
///
/// So unavailability degrades: the envelope is delivered, the skip is metered, and
/// `SealedDoorTokenCheckDegraded` fires. What is given up for the length of the outage is
/// real and worth naming — a token can be double-spent, and an envelope carrying none at
/// all passes. That is the cheaper half of the trade. The expensive half was handing an
/// attacker a messaging kill switch in exchange for it.
///
/// `NotConfigured` deliberately does NOT degrade: it means this instance has no issuer
/// key, which in production cannot happen past boot (`load_required_hex_secret` is
/// required there), so it is a deployment error and refusing loudly is how it is found.
pub(crate) fn token_gate_action(
    policy: construct_config::StealthTokenPolicy,
    result: crate::token_redeem::TokenRedeemResult,
) -> TokenGateAction {
    use crate::token_redeem::TokenRedeemResult as R;
    use construct_config::StealthTokenPolicy as P;

    if result.is_accept() {
        return TokenGateAction::Deliver;
    }
    match (policy, result) {
        // Off never reaches here (the caller skips the whole block), but a policy that
        // rejects under Off would be a surprising thing to leave expressible.
        (P::Off, _) => TokenGateAction::Deliver,
        (_, R::RedisError) => TokenGateAction::DeliverUnchecked,
        (P::Enforce, _) => TokenGateAction::Reject,
        (P::Warn, _) => TokenGateAction::Deliver,
    }
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

        // ── Intake credential, checked before anything is charged ─────────────
        // A token per sealed envelope charges the same for a stranger's first contact and for
        // the four-hundredth message between two people who have been talking for a year —
        // measured 2026-09-11, delivery receipts alone were 36–38% of all spend, and they are
        // spent by the person who was *written to*. An envelope carrying a credential the
        // recipient issued owes nothing, so this runs first and the whole redemption below is
        // skipped. See construct-docs/decisions/contact-traffic-is-vouched-not-purchased.md.
        //
        // Anything other than a match falls through to the token path, which is exactly what
        // the envelope would have done before this existed. A credential is a discount, never
        // a requirement, so a wrong one cannot be a delivery failure on its own.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let intake = {
            let mut conn = context.redis_conn.clone();
            crate::intake::check_intake_credential(
                &mut conn,
                context.token_enc_static_secret.as_ref(),
                &sealed_inner.intake_tag_sealed,
                &recipient_id,
                now_unix,
            )
            .await
        };
        construct_metrics::MSG_INTAKE_CHECK_TOTAL
            .with_label_values(&[intake.as_label()])
            .inc();

        if intake.owes_token() {
            let has_token =
                !sealed_inner.token_nonce.is_empty() && !sealed_inner.token_bytes.is_empty();
            construct_metrics::STEALTH_TOKEN_PRESENT_TOTAL
                .with_label_values(&[if has_token { "present" } else { "absent" }])
                .inc();

            let mut conn = context.redis_conn.clone();
            // Logical-message unit: `token_spend_id` shared across multi-chunk wire
            // envelopes so one Privacy Pass token pays for the whole set (album /
            // large body), not one token per chunk. The unit is bound to
            // `recipient_user_id` so a client-chosen spend_id cannot cover
            // envelopes to other users (TOKEN_SPEND_UNIT_RECIPIENT_BINDING_SPEC).
            // Empty spend_id = legacy per-envelope redemption.
            let result = crate::token_redeem::redeem_token_checked(
                &mut conn,
                context.token_issuer_key.as_ref(),
                context.token_enc_static_secret.as_ref(),
                &sealed_inner.token_nonce,
                &sealed_inner.token_bytes,
                &sealed_inner.token_spend_id,
                &recipient_id,
            )
            .await;

            let result_label = result.as_label();
            construct_metrics::STEALTH_TOKEN_CHECK_TOTAL
                .with_label_values(&[mode_label, result_label])
                .inc();

            match token_gate_action(policy, result) {
                TokenGateAction::Reject => {
                    tracing::warn!(
                        result = result_label,
                        "sealed sender: Privacy Pass token redemption failed — rejecting (enforce mode)"
                    );
                    return Err(anyhow::Error::new(TokenRejected {
                        label: result_label,
                    }));
                }
                TokenGateAction::DeliverUnchecked => {
                    construct_metrics::record_abuse_fail_open("stealth_token");
                    tracing::error!(
                        mode = mode_label,
                        "sealed sender: Privacy Pass state store unreachable — delivering without a token check"
                    );
                }
                TokenGateAction::Deliver => {
                    if !result.is_accept() {
                        tracing::info!(
                            result = result_label,
                            "sealed sender: Privacy Pass token redemption failed — allowing (warn mode)"
                        );
                    } else if policy == StealthTokenPolicy::Warn
                        && result == crate::token_redeem::TokenRedeemResult::Ok
                    {
                        // Success-path visibility for the warn-mode validation window: confirms
                        // the client→server VOPRF round-trip works end-to-end (first redemption of
                        // a real client token). unit_covered is silent (expected for multi-chunk
                        // follow-ups).
                        tracing::info!(
                            "sealed sender: Privacy Pass token redeemed OK (warn-mode validation)"
                        );
                    }
                }
            }
        } // if intake.owes_token()
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
                construct_metrics::record_abuse_fail_open("delivery_tag");
            }
        }
    }

    // The one device this envelope was encrypted for, when the sender named it.
    // Empty means "every active device of the recipient", which is what every sealed
    // envelope meant before the field existed — and why a second device in one account
    // received ciphertext it could not decrypt and a certificate it could not unseal.
    // Same normaliser as the unsealed ingress path — one rule, one place.
    let recipient_device = core::normalize_device_id(&sealed_inner.recipient_device);

    let msg_envelope = MessageEnvelope::from_sealed_sender(
        message_id.clone(),
        recipient_id,
        recipient_device,
        sealed.sealed_inner.to_vec(),
    );

    let app_context = Arc::new(context.to_app_context());
    if let Err(e) = core::dispatch_envelope(
        &app_context,
        msg_envelope,
        context.notification_context.clone(),
    )
    .await
    {
        if !sealed_inner.delivery_tag.is_empty() {
            let mut conn = context.redis_conn.clone();
            if let Err(unmark_err) =
                unmark_delivery_tag(&mut conn, &sealed_inner.delivery_tag).await
            {
                tracing::error!(
                    error = %unmark_err,
                    "delivery_tag unmark after dispatch failure failed — retry may no-op"
                );
            }
        }
        return Err(anyhow::anyhow!("{}", e));
    }

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

#[cfg(test)]
mod tests {
    use super::{TokenGateAction, token_gate_action};
    use crate::token_redeem::TokenRedeemResult as R;
    use construct_config::StealthTokenPolicy as P;

    const ALL_RESULTS: [R; 9] = [
        R::Ok,
        R::UnitCovered,
        R::MissingToken,
        R::DecryptFailed,
        R::InvalidToken,
        R::DoubleSpent,
        R::UnitExhausted,
        R::RedisError,
        R::NotConfigured,
    ];

    /// The whole point of this change: an unreachable state store must not read as a
    /// forged token. Before 2026-09-13 these two took the same branch, and the cost was
    /// that one Redis outage refused every sealed send in the system.
    #[test]
    fn enforce_refuses_a_bad_token_but_not_an_unreachable_redis() {
        assert_eq!(
            token_gate_action(P::Enforce, R::InvalidToken),
            TokenGateAction::Reject
        );
        assert_eq!(
            token_gate_action(P::Enforce, R::RedisError),
            TokenGateAction::DeliverUnchecked
        );
    }

    /// Every way a token can be *wrong* is still refused under enforce. Listed one by one
    /// rather than as "everything else", so adding a variant that should be refused and
    /// forgetting it here shows up as a missing line instead of passing by default.
    #[test]
    fn enforce_refuses_every_rejection_reason() {
        for result in [
            R::MissingToken,
            R::DecryptFailed,
            R::InvalidToken,
            R::DoubleSpent,
            R::UnitExhausted,
        ] {
            assert_eq!(
                token_gate_action(P::Enforce, result),
                TokenGateAction::Reject,
                "{} must still be refused under enforce",
                result.as_label()
            );
        }
    }

    /// A missing issuer key is a deployment error, not an outage — it cannot happen past
    /// boot in production, so refusing loudly is how it gets found. Degrading it would
    /// mean a deploy could silently turn the gate off for good.
    #[test]
    fn a_missing_issuer_key_is_not_treated_as_an_outage() {
        assert_eq!(
            token_gate_action(P::Enforce, R::NotConfigured),
            TokenGateAction::Reject
        );
    }

    /// Degradation is about *availability*, not about relaxing warn. Under warn nothing is
    /// refused either way, but the unavailable case must still be distinguishable, because
    /// that is what the metric and the alert are keyed on.
    #[test]
    fn warn_delivers_everything_but_still_names_the_unchecked_case() {
        for result in ALL_RESULTS {
            let action = token_gate_action(P::Warn, result);
            assert_ne!(
                action,
                TokenGateAction::Reject,
                "warn must never refuse ({})",
                result.as_label()
            );
        }
        assert_eq!(
            token_gate_action(P::Warn, R::RedisError),
            TokenGateAction::DeliverUnchecked,
            "an unchecked delivery under warn is still unchecked, and must be metered as such"
        );
    }

    /// An accepted token is an ordinary delivery under every policy — never the metered
    /// `DeliverUnchecked`, or the fail-open counter would count normal traffic and the
    /// alert built on it would be noise.
    #[test]
    fn an_accepted_token_is_never_reported_as_unchecked() {
        for policy in [P::Off, P::Warn, P::Enforce] {
            for result in [R::Ok, R::UnitCovered] {
                assert_eq!(
                    token_gate_action(policy, result),
                    TokenGateAction::Deliver,
                    "{} under {:?} must be a plain delivery",
                    result.as_label(),
                    policy
                );
            }
        }
    }

    #[test]
    fn off_refuses_nothing() {
        for result in ALL_RESULTS {
            assert_ne!(token_gate_action(P::Off, result), TokenGateAction::Reject);
        }
    }
}
