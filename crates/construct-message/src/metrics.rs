use once_cell::sync::Lazy;
use prometheus::{Counter, Histogram, register_counter, register_histogram};

/// Kafka producer success counter
pub static KAFKA_PRODUCE_SUCCESS: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "kafka_produce_success_total",
        "Total number of successful Kafka produce operations"
    )
    .expect("Failed to register kafka_produce_success_total metric")
});

/// Kafka producer failure counter
pub static KAFKA_PRODUCE_FAILURE: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "kafka_produce_failure_total",
        "Total number of failed Kafka produce operations"
    )
    .expect("Failed to register kafka_produce_failure_total metric")
});

/// Kafka producer latency histogram
pub static KAFKA_PRODUCE_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "kafka_produce_latency_seconds",
        "Kafka produce operation latency in seconds",
        vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
        ]
    )
    .expect("Failed to register kafka_produce_latency_seconds metric")
});

/// Kafka consumer messages processed counter
pub static KAFKA_CONSUME_SUCCESS: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "kafka_consume_success_total",
        "Total number of successfully consumed Kafka messages"
    )
    .expect("Failed to register kafka_consume_success_total metric")
});

/// Kafka consumer errors counter
pub static KAFKA_CONSUME_FAILURE: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "kafka_consume_failure_total",
        "Total number of Kafka consumer errors"
    )
    .expect("Failed to register kafka_consume_failure_total metric")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        // Just ensure metrics can be accessed without panicking
        KAFKA_PRODUCE_SUCCESS.inc();
        KAFKA_PRODUCE_FAILURE.inc();
        KAFKA_PRODUCE_LATENCY.observe(0.1);
        KAFKA_CONSUME_SUCCESS.inc();
        KAFKA_CONSUME_FAILURE.inc();
    }
}
