//! Prometheus metrics for Construct server
//!
//! Provides centralized metrics collection for monitoring:
//! - Message delivery
//! - Shadow-read comparisons (Kafka vs Redis)
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
// Shadow-Read Metrics (Kafka vs Redis Comparison)
// ============================================================================

/// Messages that matched between Kafka and Redis
pub static SHADOW_READ_MATCHES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_matches_total",
        "Messages that matched between Kafka and Redis offline queue"
    ))
    .expect("Failed to register SHADOW_READ_MATCHES metric")
});

/// Messages that differed between Kafka and Redis
pub static SHADOW_READ_DISCREPANCIES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_discrepancies_total",
        "Messages that differed between Kafka and Redis offline queue"
    ))
    .expect("Failed to register SHADOW_READ_DISCREPANCIES metric")
});

/// Messages found in Kafka but not in Redis
pub static SHADOW_READ_KAFKA_ONLY: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_kafka_only_total",
        "Messages present in Kafka but not in Redis offline queue"
    ))
    .expect("Failed to register SHADOW_READ_KAFKA_ONLY metric")
});

/// Messages found in Redis but not in Kafka (reverse-check)
pub static SHADOW_READ_REDIS_ONLY: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_redis_only_total",
        "Messages present in Redis offline queue but not seen in Kafka"
    ))
    .expect("Failed to register SHADOW_READ_REDIS_ONLY metric")
});

/// Total messages processed in shadow-read mode
pub static SHADOW_READ_PROCESSED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_processed_total",
        "Total messages processed in shadow-read mode"
    ))
    .expect("Failed to register SHADOW_READ_PROCESSED metric")
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
}
