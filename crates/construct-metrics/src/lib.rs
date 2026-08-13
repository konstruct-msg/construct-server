//! Prometheus metrics for Construct server
//!
//! Provides centralized metrics collection for monitoring:
//! - Message delivery
//! - Gateway performance
//! - Circuit breaker states
//! - Service health
//! - Session lifecycle (init, END_SESSION, healing)
//! - OTPK key inventory
//! - Active gRPC streams
//! - Key Transparency proof failures

use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    TextEncoder, opts, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
};

// ============================================================================
// Message Metrics
// ============================================================================

/// Total number of messages sent
pub static MESSAGES_SENT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_messages_sent_total",
        "Total number of messages sent"
    ))
    .expect("Failed to register MESSAGES_SENT_TOTAL metric")
});

/// Legacy edit RPC usage counter.
/// Incremented when a client calls the deprecated EditMessage RPC.
/// Used to gauge fleet migration before the RPC is fully removed.
pub static LEGACY_EDIT_USAGE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_legacy_edit_usage_total",
            "Deprecated EditMessage RPC usage by source"
        ),
        &["source"]
    )
    .expect("Failed to register LEGACY_EDIT_USAGE_TOTAL metric")
});

/// Histogram of message delivery times
#[allow(dead_code)]
pub static MESSAGE_DELIVERY_TIME: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "construct_message_delivery_time_seconds",
        "Histogram of message delivery times"
    )
    .expect("Failed to register MESSAGE_DELIVERY_TIME metric")
});

// ============================================================================
// Gateway Metrics
// ============================================================================

/// Gateway requests total (by service and status code)
pub static GATEWAY_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "gateway_requests_total",
            "Total number of requests processed by gateway"
        ),
        &["service", "status_code"]
    )
    .expect("Failed to register GATEWAY_REQUESTS_TOTAL metric")
});

/// Gateway request duration in seconds (histogram)
pub static GATEWAY_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gateway_request_duration_seconds",
        "Request duration in seconds",
        &["service"]
    )
    .expect("Failed to register GATEWAY_REQUEST_DURATION_SECONDS metric")
});

/// Circuit breaker state (0=Closed, 1=Open, 2=HalfOpen)
pub static GATEWAY_CIRCUIT_BREAKER_STATE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        opts!(
            "gateway_circuit_breaker_state",
            "Circuit breaker state (0=Closed, 1=Open, 2=HalfOpen)"
        ),
        &["service"]
    )
    .expect("Failed to register GATEWAY_CIRCUIT_BREAKER_STATE metric")
});

/// Service health status (1=healthy, 0=unhealthy)
/// Which build is running, as labels on a constant 1.
///
/// The standard Prometheus `*_build_info` pattern: the value carries no
/// information, the labels do. It exists because the workspace semver could not
/// answer "what is deployed?" — it only moves on a manual bump, so many commits
/// share one number. `count(count by (commit) (construct_build_info)) > 1` then
/// means a partial rollout: some containers on the old image, some on the new.
pub static BUILD_INFO: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        opts!(
            "construct_build_info",
            "Build identity of the running binary (always 1; read the labels)"
        ),
        &["service", "version", "commit"]
    )
    .expect("Failed to register BUILD_INFO metric")
});

pub static GATEWAY_SERVICE_HEALTH: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        opts!(
            "gateway_service_health",
            "Service health status (1=healthy, 0=unhealthy)"
        ),
        &["service"]
    )
    .expect("Failed to register GATEWAY_SERVICE_HEALTH metric")
});

// ============================================================================
// Calls / Signaling Metrics
// ============================================================================

/// Total initiated calls (offer received).
pub static CALLS_INITIATED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_calls_initiated_total",
            "Total number of calls initiated (offer received)"
        ),
        &["type"]
    )
    .expect("Failed to register CALLS_INITIATED_TOTAL metric")
});

/// Total connected calls (offer -> answer).
pub static CALLS_CONNECTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_calls_connected_total",
        "Total number of calls successfully connected (offer -> answer)"
    ))
    .expect("Failed to register CALLS_CONNECTED_TOTAL metric")
});

/// Total missed calls (ringing -> timeout without answer).
pub static CALLS_MISSED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_calls_missed_total",
        "Total number of calls missed (timeout without answer)"
    ))
    .expect("Failed to register CALLS_MISSED_TOTAL metric")
});

/// Total declined calls (hangup declined).
pub static CALLS_DECLINED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_calls_declined_total",
        "Total number of calls declined (hangup declined)"
    ))
    .expect("Failed to register CALLS_DECLINED_TOTAL metric")
});

/// Total failed calls (connection failed / keepalive timeout).
pub static CALLS_FAILED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_calls_failed_total",
        "Total number of calls failed (connection failed)"
    ))
    .expect("Failed to register CALLS_FAILED_TOTAL metric")
});

/// Total signaling errors returned to clients.
pub static SIGNALING_ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_signaling_errors_total",
            "Total number of signaling errors returned"
        ),
        &["code"]
    )
    .expect("Failed to register SIGNALING_ERRORS_TOTAL metric")
});

/// Call setup duration (seconds) from offer receipt to answer.
pub static CALL_SETUP_DURATION_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "construct_call_setup_duration_seconds",
        "Call setup duration in seconds (offer -> answer)"
    )
    .expect("Failed to register CALL_SETUP_DURATION_SECONDS metric")
});

/// Current number of active calls (including pending attempts).
pub static ACTIVE_CALLS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "construct_active_calls",
        "Current number of active calls (including pending attempts)"
    )
    .expect("Failed to register ACTIVE_CALLS metric")
});

/// Placeholder: total calls relayed via TURN (incremented by clients / media plane later).
#[allow(dead_code)]
pub static CALLS_TURN_RELAYED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_calls_turn_relayed_total",
        "Total number of calls relayed via TURN (not P2P)"
    ))
    .expect("Failed to register CALLS_TURN_RELAYED_TOTAL metric")
});

/// Placeholder: active TURN allocations (set by TURN service later).
#[allow(dead_code)]
pub static TURN_ACTIVE_ALLOCATIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "construct_turn_active_allocations",
        "Current number of active TURN allocations"
    )
    .expect("Failed to register TURN_ACTIVE_ALLOCATIONS metric")
});

// ============================================================================
// Session Lifecycle Metrics
// ============================================================================

/// Session initialisations that completed successfully.
/// Label `side`: "initiator" | "responder"
pub static SESSION_INIT_SUCCESS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_session_init_success_total",
            "Session X3DH initialisations completed successfully"
        ),
        &["side"]
    )
    .expect("Failed to register SESSION_INIT_SUCCESS_TOTAL metric")
});

/// Session initialisations that failed.
/// Label `reason`: "decrypt_failed" | "bundle_fetch_failed" | "otpk_exhausted" | "timeout" | "other"
pub static SESSION_INIT_FAILURE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_session_init_failure_total",
            "Session X3DH initialisations that failed"
        ),
        &["reason"]
    )
    .expect("Failed to register SESSION_INIT_FAILURE_TOTAL metric")
});

/// END_SESSION signals sent to peers.
/// Label `reason`: "init_failed" | "manual_reset" | "heal_failed" | "peer_request"
pub static END_SESSION_SENT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_end_session_sent_total",
            "END_SESSION signals sent to peers"
        ),
        &["reason"]
    )
    .expect("Failed to register END_SESSION_SENT_TOTAL metric")
});

/// Session healing attempts triggered by decrypt failure on msgNum=0.
pub static SESSION_HEAL_ATTEMPTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_session_heal_attempts_total",
        "Session healing attempts triggered by decryption failure"
    ))
    .expect("Failed to register SESSION_HEAL_ATTEMPTS_TOTAL metric")
});

/// Session healing attempts that resulted in a recovered session.
pub static SESSION_HEAL_SUCCESS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_session_heal_success_total",
        "Session healing attempts that successfully recovered the session"
    ))
    .expect("Failed to register SESSION_HEAL_SUCCESS_TOTAL metric")
});

// ============================================================================
// OTPK / Key Inventory Metrics
// ============================================================================

/// Current number of one-time pre-keys available on the server for a device.
/// Label `service`: the key-service instance (useful when sharded).
/// This is a Gauge because the value goes both up (upload) and down (consumption).
pub static OTPK_REMAINING: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "construct_otpk_remaining",
        "Current number of one-time pre-keys available for the local device"
    )
    .expect("Failed to register OTPK_REMAINING metric")
});

/// Total OTPKs uploaded to the server (cumulative).
pub static OTPK_UPLOADED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_otpk_uploaded_total",
        "Total one-time pre-keys uploaded to key service"
    ))
    .expect("Failed to register OTPK_UPLOADED_TOTAL metric")
});

/// Total OTPKs consumed by incoming session initialisations (cumulative).
pub static OTPK_CONSUMED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_otpk_consumed_total",
        "Total one-time pre-keys consumed by incoming session initialisations"
    ))
    .expect("Failed to register OTPK_CONSUMED_TOTAL metric")
});

// ============================================================================
// gRPC Stream Metrics
// ============================================================================

/// Current number of open gRPC message-stream connections.
pub static GRPC_STREAMS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "construct_grpc_streams_active",
        "Current number of active gRPC message-stream (subscribe) connections"
    )
    .expect("Failed to register GRPC_STREAMS_ACTIVE metric")
});

/// Total gRPC stream reconnections (client reconnected after disconnect).
pub static GRPC_STREAM_RECONNECTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_grpc_stream_reconnects_total",
        "Total number of gRPC message-stream reconnections"
    ))
    .expect("Failed to register GRPC_STREAM_RECONNECTS_TOTAL metric")
});

/// Poll started with `last_stream_id = None` after Subscribe already carried a
/// `since_cursor`. After the catch-up-after-subscribe fix this must stay at zero —
/// a non-zero value means the open-time race (or a similar ordering bug) regressed.
pub static MSG_POLL_MISSING_CURSOR_AFTER_SUBSCRIBE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_msg_poll_missing_cursor_after_subscribe_total",
        "MessageStream poll started without cursor after Subscribe carried since_cursor (regression canary)"
    ))
    .expect("Failed to register MSG_POLL_MISSING_CURSOR_AFTER_SUBSCRIBE_TOTAL metric")
});

/// Silent APNs `new_message` push skipped because the recipient already has an
/// active MessageStream (`user:{id}:server_instance_id` present). Realtime delivery
/// uses Redis `inbox:wakeup` — pushing while online causes client reconnect storms
/// and full offline-stream redelivery.
pub static MSG_PUSH_SKIPPED_ONLINE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_msg_push_skipped_online_total",
        "Blind new_message pushes skipped because recipient has an active MessageStream"
    ))
    .expect("Failed to register MSG_PUSH_SKIPPED_ONLINE_TOTAL metric")
});

/// Offline stream XTRIM driven by client `since_cursor` (durable ACK).
/// Label `path`: "subscribe" | "get_pending"
pub static MSG_OFFLINE_TRIM_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_msg_offline_trim_total",
            "Offline delivery stream trims driven by client since_cursor ACK"
        ),
        &["path"]
    )
    .expect("Failed to register MSG_OFFLINE_TRIM_TOTAL metric")
});

// ============================================================================
// Security / Key Transparency Metrics
// ============================================================================

/// Key Transparency inclusion/consistency proof failures.
/// Label `proof_type`: "inclusion" | "consistency" | "root_mismatch"
pub static KT_PROOF_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_kt_proof_failures_total",
            "Key Transparency proof verification failures"
        ),
        &["proof_type"]
    )
    .expect("Failed to register KT_PROOF_FAILURES_TOTAL metric")
});

/// Authentication failures (JWT validation, device not found, etc.).
/// Label `reason`: "invalid_token" | "expired" | "device_not_found" | "permission_denied"
///   | "refresh_token_consumed" | "refresh_token_revoked" | "redis_unavailable"
pub static AUTH_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_auth_failures_total",
            "Authentication failures by reason"
        ),
        &["reason"]
    )
    .expect("Failed to register AUTH_FAILURES_TOTAL metric")
});

// ============================================================================
// Stealth Sealed Sender — Privacy Pass Redemption (Phase 1)
// ============================================================================

/// Sealed-sender messages dispatched locally (i.e. actually decoded and
/// evaluated for token redemption — excludes opaque cross-server forwards).
pub static STEALTH_SEALED_LOCAL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_stealth_sealed_local_total",
        "Sealed-sender messages dispatched to a local recipient"
    ))
    .expect("Failed to register STEALTH_SEALED_LOCAL_TOTAL metric")
});

/// Whether a locally-dispatched sealed message carried a Privacy Pass token.
/// Label `presence`: "present" | "absent"
pub static STEALTH_TOKEN_PRESENT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_stealth_token_present_total",
            "Sealed-sender messages by whether a Privacy Pass token was attached"
        ),
        &["presence"]
    )
    .expect("Failed to register STEALTH_TOKEN_PRESENT_TOTAL metric")
});

/// Result of a Privacy Pass token redemption attempt.
/// Label `mode`: "warn" | "enforce"
/// Label `result`: "ok" | "unit_covered" | "missing_token" | "decrypt_failed"
///   | "invalid_token" | "double_spent" | "unit_exhausted" | "redis_error"
///   | "not_configured"
pub static STEALTH_TOKEN_CHECK_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_stealth_token_check_total",
            "Privacy Pass token redemption outcomes for sealed-sender messages"
        ),
        &["mode", "result"]
    )
    .expect("Failed to register STEALTH_TOKEN_CHECK_TOTAL metric")
});

// ============================================================================
// Abuse-control fail-open (messaging availability bias)
// ============================================================================
//
// Messaging prefers delivery over hard-blocking when Redis (or related) is
// unavailable. Each intentional fail-open branch increments this counter so
// operators can alert when abuse controls are degraded.
//
// Label `control` (stable names — do not rename without dashboard updates):
//   send_dedup          — SendMessage idempotency / duplicate check
//   dispatch_dedup      — dispatch_envelope dedup mark/check
//   sentinel            — SentinelCore::check_send_permission outer Err
//   rate_trust          — TrustLevel + hourly/fanout limits skipped (Redis down)
//   sealed_ip           — per-IP sealed-sender rate limit
//   delivery_tag        — sealed delivery_tag replay cache
//   federation_origin   — federation per-origin rate limit
//   otpk_drain_check    — key-service OTPK drain threshold (Redis GET)
//   otpk_drain_record   — key-service OTPK drain counter (Redis INCR)
//   voip_push           — VoIP push recipient/peer rate limit (Redis)
//
// Policy (launch): fail-open remains intentional. Alert when rate of any label
// is non-zero for sustained periods (Redis outage or misconfig).

/// Abuse / anti-spam controls skipped due to infrastructure error (fail-open).
pub static MSG_ABUSE_FAIL_OPEN_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_msg_abuse_fail_open_total",
            "Messaging abuse controls skipped (fail-open) by control name"
        ),
        &["control"]
    )
    .expect("Failed to register MSG_ABUSE_FAIL_OPEN_TOTAL metric")
});

/// Record that an abuse control was skipped (fail-open). Prefer stable `control` labels.
#[inline]
pub fn record_abuse_fail_open(control: &'static str) {
    MSG_ABUSE_FAIL_OPEN_TOTAL
        .with_label_values(&[control])
        .inc();
}

// ============================================================================
// Auth security fail-open (login anti-bruteforce availability bias)
// ============================================================================
//
// Temporary login lockout uses Redis. When Redis is unavailable we prefer
// allowing login attempts over denying all auth (availability). Each skip is
// metered so operators can alert during Redis outages / lockout degradation.
//
// Label `control` (stable):
//   login_block_check  — is_user_blocked GET failed (cannot enforce existing ban)
//   login_fail_count   — increment_failed_login_count failed
//   login_block_apply  — block_user_temporarily failed after max attempts
//   login_fail_reset   — reset_failed_login_count failed after success
//
// Policy (launch): fail-open on Redis for these controls. Alert on sustained rate.

/// Auth anti-bruteforce controls skipped due to infrastructure error (fail-open).
pub static AUTH_SECURITY_FAIL_OPEN_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_auth_security_fail_open_total",
            "Auth security controls skipped (fail-open) by control name"
        ),
        &["control"]
    )
    .expect("Failed to register AUTH_SECURITY_FAIL_OPEN_TOTAL metric")
});

/// Record that an auth security control was skipped (fail-open).
#[inline]
pub fn record_auth_security_fail_open(control: &'static str) {
    AUTH_SECURITY_FAIL_OPEN_TOTAL
        .with_label_values(&[control])
        .inc();
}

// ============================================================================
// Metrics Collection
// ============================================================================

/// Gather all registered metrics and encode as Prometheus text format
pub fn gather_metrics() -> Result<String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer)?;

    Ok(String::from_utf8(buffer)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gather_metrics() {
        // Increment a counter to ensure metrics are registered
        MESSAGES_SENT_TOTAL.inc();

        let result = gather_metrics();
        assert!(result.is_ok());

        let metrics_text = result.unwrap();
        assert!(metrics_text.contains("construct_messages_sent_total"));
    }

    #[test]
    fn test_abuse_fail_open_metric() {
        record_abuse_fail_open("sentinel");
        record_abuse_fail_open("sealed_ip");
        let text = gather_metrics().unwrap();
        assert!(text.contains("construct_msg_abuse_fail_open_total"));
        assert!(text.contains("control=\"sentinel\"") || text.contains("sentinel"));
    }

    #[test]
    fn test_auth_security_fail_open_metric() {
        record_auth_security_fail_open("login_block_apply");
        record_auth_security_fail_open("login_fail_count");
        let text = gather_metrics().unwrap();
        assert!(text.contains("construct_auth_security_fail_open_total"));
        assert!(
            text.contains("control=\"login_block_apply\"") || text.contains("login_block_apply")
        );
    }
}
