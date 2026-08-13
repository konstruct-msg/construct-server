//! Prometheus metrics for Construct server
//!
//! Provides centralized metrics collection for monitoring:
//! - Message delivery
//! - Service health and build identity
//! - OTPK inventory across the fleet
//! - Active gRPC message streams
//!
//! What is deliberately NOT here: anything only a client can observe. Session
//! setup, healing, END_SESSION and Key Transparency proofs all happen inside
//! the E2EE envelope, and a server-side counter for them could only be filled
//! by clients reporting on themselves. Declarations for those existed here
//! until 2026-08-13 with no producer, and a Grafana row was built on them.

use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, GaugeVec, Histogram, IntCounter, IntCounterVec, IntGauge, TextEncoder, opts,
    register_gauge_vec, register_histogram, register_int_counter, register_int_counter_vec,
    register_int_gauge,
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

// `gateway_requests_total`, `gateway_request_duration_seconds` and
// `gateway_circuit_breaker_state` were removed on 2026-08-13. They were declared
// when the gateway proxied the API; it no longer does — its router serves
// /health, /metrics and /.well-known, and every real request goes
// client → Caddy → service over h2c. Instrumenting them would have measured
// health checks and called it request latency.
//
// Per-request latency and errors now come from Caddy itself
// (`caddy_http_requests_total`, `caddy_http_request_duration_seconds`), which is
// the only process that sees them. See the `metrics` global option and the
// `:2020` block in ops/Caddyfile, and the `caddy` scrape job.

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

// TURN metrics (`construct_calls_turn_relayed_total`,
// `construct_turn_active_allocations`) were removed on 2026-08-13. They were
// declared as placeholders for "the TURN service later"; allocation counts live
// inside coturn, so the way to get them is a coturn exporter as a scrape target,
// not a Rust static nothing can reach.

// ============================================================================
// Session Lifecycle Metrics — REMOVED 2026-08-13
// ============================================================================
//
// construct_session_init_{success,failure}_total, construct_end_session_sent_total
// and construct_session_heal_{attempts,success}_total lived here for months with
// no producer, and the Grafana overview had a whole row built on them showing
// "No data".
//
// They cannot be produced. Session setup, healing and END_SESSION are decisions
// made between two clients inside the E2EE envelope; the server relays sealed
// payloads and cannot observe any of it — that is the property being sold. The
// only way to fill these would be for clients to report their session state,
// which is telemetry, and the product's answer to telemetry is that there is
// none.

// ============================================================================
// OTPK / Key Inventory Metrics
// ============================================================================
//
// Fleet-wide counts, never per device. A gauge labelled by device_id would put
// an identifier for every account into a metrics endpoint — precisely the shape
// of data this product exists not to hold — and it would be unbounded
// cardinality besides. These three answer the operational question ("can devices
// still start new sessions?") without naming anyone.
//
// The first reading, 2026-08-13: 123 active devices, 76 of them at zero — but
// read that with its denominator. `devices` has no last-seen column, so every
// device ever registered and not deactivated is counted forever. By month of
// registration: March 35 of 35 exhausted, April 26 of 29, June 3 of 21, August
// 1 of 5. The 76 is mostly abandoned test registrations from before the fleet
// replenished properly, not live devices failing now. The slope is the signal;
// the absolute number will stay pessimistic until there is a last-seen column.

/// Active devices known to the server, denominator for the two below.
pub static OTPK_DEVICES_TOTAL: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "construct_otpk_devices_total",
        "Active devices, as the denominator for OTPK inventory"
    )
    .expect("Failed to register OTPK_DEVICES_TOTAL metric")
});

/// Devices under the low-water mark — they still work, but not for long.
pub static OTPK_DEVICES_LOW: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "construct_otpk_devices_low",
        "Active devices with fewer than 10 unexpired one-time pre-keys"
    )
    .expect("Failed to register OTPK_DEVICES_LOW metric")
});

/// Devices with none left. A peer contacting one of these gets an SPK-only
/// bundle: the session still establishes, but without the one-time key, so the
/// initial message loses the forward secrecy that key provides. Silent, and
/// invisible to both users.
pub static OTPK_DEVICES_EXHAUSTED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "construct_otpk_devices_exhausted",
        "Active devices with zero unexpired one-time pre-keys"
    )
    .expect("Failed to register OTPK_DEVICES_EXHAUSTED metric")
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

/// Message streams opened. Together with the gauge above this is churn: a high
/// open rate against a flat active count means clients are reconnecting in a
/// loop, which has cost real incidents here (signalling slowed by MessageStream
/// churn) and is invisible from the gauge alone.
pub static GRPC_STREAMS_OPENED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_grpc_streams_opened_total",
        "Message streams opened since process start"
    ))
    .expect("Failed to register GRPC_STREAMS_OPENED_TOTAL metric")
});

/// Message streams closed, by reason.
///
/// The reasons are the ones the stream loop already computes for its closing log
/// line — `client_disconnect`, `client_eof`, `handler_error`, `stream_error`,
/// `heartbeat_tx_closed`, `all_channels_closed`. Naming this "reconnects", as
/// the previous declaration did, would have hidden the only distinction that
/// matters: whether the client left or the server dropped it.
pub static GRPC_STREAMS_CLOSED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_grpc_streams_closed_total",
            "Message streams closed, by close reason"
        ),
        &["reason"]
    )
    .expect("Failed to register GRPC_STREAMS_CLOSED_TOTAL metric")
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

// construct_kt_proof_failures_total was removed on 2026-08-13, for the same
// reason as the session metrics: KT inclusion and consistency proofs are
// verified by the client against the log. A proof failing is exactly the case
// where the server is the suspect, so a server-side counter for it would be
// evidence supplied by the accused.

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

/// Force every metric that something can actually write into the registry.
///
/// `Lazy` registers on first deref, so a counter that has not yet been
/// incremented does not exist as far as Prometheus is concerned — and a missing
/// series is not zero, it is *nothing*. Grafana prints "No data" over a red
/// background, which is what an outage looks like, for the ordinary state of an
/// idle server. Worse, it resets on restart: `construct_msg_offline_trim_total`
/// had series three hours before this was written and none afterwards, purely
/// because messaging-service was redeployed in between.
///
/// Called once from the shared `/metrics` handler, so every service gets it
/// without eight separate places to forget it.
///
/// Only metrics with a real producer are listed. Registering the rest would put
/// a permanent, authoritative-looking `0` on screen for something nothing can
/// ever increment — a worse lie than the blank. `*Vec` metrics register the
/// family but emit no sample until a label set exists, which is correct: we do
/// not know the labels in advance and inventing one would fabricate a series.
///
/// Nor is every real metric listed. This function runs in all seven services, so
/// forcing one here makes all seven report it. That is right for a metric about
/// the process ("this service has 0 active streams" is true) and wrong for one
/// about global state: `construct_otpk_devices_exhausted` is computed by
/// key-service from the database, and media-service reporting 0 is not a low
/// reading, it is a service answering a question it was never asked. Six flat
/// zeros beside one real line is the same false reassurance as a blank panel,
/// only harder to notice. The fleet gauges are therefore left to appear when
/// key-service's inventory poll first sets them, within a minute of boot.
pub fn init_registry() {
    Lazy::force(&MESSAGES_SENT_TOTAL);
    Lazy::force(&MESSAGE_DELIVERY_TIME);
    Lazy::force(&CALLS_CONNECTED_TOTAL);
    Lazy::force(&CALLS_MISSED_TOTAL);
    Lazy::force(&CALLS_DECLINED_TOTAL);
    Lazy::force(&CALLS_FAILED_TOTAL);
    Lazy::force(&CALL_SETUP_DURATION_SECONDS);
    Lazy::force(&ACTIVE_CALLS);
    Lazy::force(&MSG_POLL_MISSING_CURSOR_AFTER_SUBSCRIBE_TOTAL);
    Lazy::force(&MSG_PUSH_SKIPPED_ONLINE_TOTAL);
    Lazy::force(&STEALTH_SEALED_LOCAL_TOTAL);
    Lazy::force(&OTPK_UPLOADED_TOTAL);
    Lazy::force(&OTPK_CONSUMED_TOTAL);
    Lazy::force(&GRPC_STREAMS_ACTIVE);
    Lazy::force(&GRPC_STREAMS_OPENED_TOTAL);

    // Families only — no children until a label set is produced.
    Lazy::force(&LEGACY_EDIT_USAGE_TOTAL);
    Lazy::force(&CALLS_INITIATED_TOTAL);
    Lazy::force(&SIGNALING_ERRORS_TOTAL);
    Lazy::force(&MSG_OFFLINE_TRIM_TOTAL);
    Lazy::force(&AUTH_FAILURES_TOTAL);
    Lazy::force(&STEALTH_TOKEN_PRESENT_TOTAL);
    Lazy::force(&STEALTH_TOKEN_CHECK_TOTAL);
    Lazy::force(&GRPC_STREAMS_CLOSED_TOTAL);
    Lazy::force(&MSG_ABUSE_FAIL_OPEN_TOTAL);
    Lazy::force(&AUTH_SECURITY_FAIL_OPEN_TOTAL);
}

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

    /// The distinction this whole function exists for: after init, an untouched
    /// counter must be present with the value 0, not absent.
    ///
    /// Written against a real symptom. On 2026-08-13 the Grafana overview was
    /// almost entirely "No data" — nineteen panels — and the natural reading was
    /// that the server was broken. It was idle. A counter at 0 says "measured,
    /// nothing happened"; a missing series says nothing at all, and the two are
    /// indistinguishable on screen.
    ///
    /// Note the counter chosen: MSG_PUSH_SKIPPED_ONLINE_TOTAL is incremented
    /// nowhere in this test file, so if `init_registry` stops forcing it the
    /// assertion fails. Using MESSAGES_SENT_TOTAL would have passed regardless,
    /// because test_gather_metrics increments it — tests in one binary share the
    /// default registry.
    #[test]
    fn test_init_registry_makes_untouched_counters_visible_as_zero() {
        init_registry();
        let text = gather_metrics().unwrap();
        assert!(
            text.contains("construct_msg_push_skipped_online_total 0"),
            "expected an untouched counter to report 0, got:\n{}",
            text.lines()
                .filter(|l| l.contains("push_skipped"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The other half of the rule: metrics nothing can write must NOT be
    /// registered. A permanent, authoritative 0 for something no code path
    /// increments is a worse lie than a blank panel — it looks measured.
    #[test]
    fn test_init_registry_does_not_register_unproduced_metrics() {
        init_registry();
        let text = gather_metrics().unwrap();
        for orphan in [
            // Removed entirely on 2026-08-13 — see the comments where each used
            // to be declared. Named here so that reintroducing one without a
            // producer fails loudly instead of reappearing on a dashboard.
            "construct_otpk_remaining",
            // Real metrics, but only key-service can answer them — see the note
            // on init_registry. Present here because a service that does not
            // compute a fleet number must not publish a zero for it.
            "construct_otpk_devices_exhausted",
            "construct_otpk_devices_total",
            "construct_session_heal_attempts_total",
            "construct_turn_active_allocations",
            "construct_kt_proof_failures_total",
            "gateway_requests_total",
        ] {
            assert!(
                !text.contains(orphan),
                "{orphan} must not be registered by init_registry: it either has \
                 no producer at all, or has one in a single service — and this \
                 function runs in all seven. Both cases put a zero on the \
                 dashboard that nothing stands behind."
            );
        }
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
