//! Prometheus metrics for Construct server
//!
//! Provides centralized metrics collection for monitoring:
//! - Message delivery
//! - Shadow-read comparisons (Kafka vs Redis)
//! - Gateway performance
//! - Circuit breaker states
//! - Service health

use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, TextEncoder, opts,
    register_gauge_vec, register_histogram, register_histogram_vec, register_int_counter,
    register_int_counter_vec,
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
