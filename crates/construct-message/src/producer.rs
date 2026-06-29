// ============================================================================
// MessageProducer — no-op stub.
//
// The Kafka/Redpanda transport was removed (KAFKA_ENABLED was always false in
// production; message delivery is Redis-direct). This stub keeps the public API
// so callers that still hold a `MessageProducer` compile; every operation is a
// no-op returning the sentinel `(-1, -1)` partition/offset.
// ============================================================================

use std::time::Duration;

use super::circuit_breaker::CircuitBreakerError;
use super::types::{DeliveryAckEvent, MessageEnvelope};
use construct_config::KafkaConfig;

/// No-op MessageProducer. All send operations succeed immediately without I/O.
#[derive(Clone)]
pub struct MessageProducer {
    topic: String,
}

impl MessageProducer {
    pub fn new(config: &KafkaConfig) -> anyhow::Result<Self> {
        Ok(Self {
            topic: config.topic.clone(),
        })
    }

    pub async fn send_message(
        &self,
        _envelope: &MessageEnvelope,
    ) -> Result<(i32, i64), CircuitBreakerError<anyhow::Error>> {
        Ok((-1, -1))
    }

    pub async fn send_delivery_ack(&self, _event: &DeliveryAckEvent) -> anyhow::Result<(i32, i64)> {
        Ok((-1, -1))
    }

    pub async fn flush(&self, _timeout: Duration) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        false
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub async fn send_raw_to_topic(
        &self,
        _topic: &str,
        _key: &[u8],
        _payload: &[u8],
    ) -> anyhow::Result<(i32, i64)> {
        Ok((-1, -1))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use construct_config::KafkaConfig;

    fn disabled_config() -> KafkaConfig {
        KafkaConfig {
            enabled: false,
            brokers: "localhost:9092".to_string(),
            topic: "test-topic".to_string(),
            consumer_group: "test-group".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            producer_compression: String::from("gzip"),
            producer_acks: String::from("all"),
            producer_linger_ms: 5,
            producer_batch_size: 1024,
            producer_max_in_flight: 10,
            producer_retries: 3,
            producer_request_timeout_ms: 10000,
            producer_delivery_timeout_ms: 30000,
            producer_enable_idempotence: true,
        }
    }

    #[test]
    fn test_disabled_producer_creation() {
        let producer = MessageProducer::new(&disabled_config());
        assert!(producer.is_ok());
        assert!(!producer.unwrap().is_enabled());
    }

    #[tokio::test]
    async fn test_disabled_producer_send() {
        let producer = MessageProducer::new(&disabled_config()).unwrap();
        let envelope = MessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "user-456".to_string(),
            "user-789".to_string(),
            vec![0u8; 32],
            42,
            "encrypted".to_string(),
            "hash123".to_string(),
        );
        let result = producer.send_message(&envelope).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (-1, -1));
    }
}
