// ============================================================================
// MessageConsumer — no-op stub.
//
// The Kafka/Redpanda transport was removed (delivery is Redis-direct; the
// delivery-worker that consumed Kafka was merged into messaging-service). This
// stub keeps the public type; construction always errors since there is no
// Kafka to consume from.
// ============================================================================

use std::time::Duration;

use super::types::MessageEnvelope;
use construct_config::KafkaConfig;

/// No-op MessageConsumer stub — cannot poll, always errors on construction.
pub struct MessageConsumer;

impl MessageConsumer {
    pub fn new(_config: &KafkaConfig) -> anyhow::Result<Self> {
        anyhow::bail!("Kafka transport has been removed — delivery is Redis-direct")
    }

    pub async fn poll(&self, _timeout: Duration) -> anyhow::Result<Option<MessageEnvelope>> {
        anyhow::bail!("Kafka transport has been removed")
    }

    pub async fn poll_raw(&self, _timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        anyhow::bail!("Kafka transport has been removed")
    }

    pub fn commit(&self) -> anyhow::Result<()> {
        anyhow::bail!("Kafka transport has been removed")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_creation_always_fails() {
        let config = KafkaConfig {
            enabled: false,
            brokers: "localhost:9092".to_string(),
            topic: "test-topic".to_string(),
            consumer_group: "test-group".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            producer_compression: "snappy".to_string(),
            producer_acks: "all".to_string(),
            producer_linger_ms: 0,
            producer_batch_size: 16384,
            producer_max_in_flight: 5,
            producer_retries: 10,
            producer_request_timeout_ms: 30000,
            producer_delivery_timeout_ms: 60000,
            producer_enable_idempotence: true,
        };

        let result = MessageConsumer::new(&config);
        assert!(result.is_err());
    }
}
