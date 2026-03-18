// ============================================================================
// MessageConsumer — Kafka/Redpanda implementation
// Compiled only when the "kafka" feature is enabled.
// Without the feature, the no-op stub below is used instead.
// ============================================================================

#[cfg(feature = "kafka")]
use anyhow::Context;
#[cfg(feature = "kafka")]
use rdkafka::Message;
#[cfg(feature = "kafka")]
use rdkafka::consumer::{Consumer, StreamConsumer};
use std::time::Duration;
#[cfg(feature = "kafka")]
use tracing::{error, info};

#[cfg(feature = "kafka")]
use super::config::create_client_config;
use super::types::KafkaMessageEnvelope;
use construct_config::KafkaConfig;

// ============================================================================
// Kafka implementation (feature = "kafka")
// ============================================================================

#[cfg(feature = "kafka")]
/// Kafka message consumer for delivery worker
pub struct MessageConsumer {
    consumer: StreamConsumer,
    #[allow(dead_code)]
    topic: String,
}

#[cfg(feature = "kafka")]
impl MessageConsumer {
    pub fn new(config: &KafkaConfig) -> anyhow::Result<Self> {
        if !config.enabled {
            anyhow::bail!("Cannot create Kafka consumer when Kafka is disabled");
        }

        info!("Initializing Kafka consumer...");
        let mut client_config = create_client_config(config)?;

        let consumer: StreamConsumer = client_config
            .set("group.id", &config.consumer_group)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("allow.auto.create.topics", "true")
            .set("fetch.min.bytes", "1")
            .set("fetch.wait.max.ms", "500")
            .set("max.partition.fetch.bytes", "1048576")
            .set("session.timeout.ms", "30000")
            .set("heartbeat.interval.ms", "3000")
            .set("max.poll.interval.ms", "300000")
            .create()
            .context("Failed to create Kafka consumer")?;

        consumer
            .subscribe(&[&config.topic])
            .context("Failed to subscribe to Kafka topic")?;

        info!(
            "Kafka consumer initialized for topic '{}' in group '{}'",
            config.topic, config.consumer_group
        );

        Ok(Self {
            consumer,
            topic: config.topic.clone(),
        })
    }

    pub async fn poll(&self, _timeout: Duration) -> anyhow::Result<Option<KafkaMessageEnvelope>> {
        match self.consumer.recv().await {
            Ok(message) => {
                let payload = message.payload().context("Message payload is empty")?;
                let envelope: KafkaMessageEnvelope = serde_json::from_slice(payload)
                    .context("Failed to deserialize message envelope")?;
                Ok(Some(envelope))
            }
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                Err(anyhow::anyhow!("Consumer error: {}", e))
            }
        }
    }

    pub async fn poll_raw(&self, _timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        match self.consumer.recv().await {
            Ok(message) => {
                let payload = message.payload().context("Message payload is empty")?;
                Ok(Some(payload.to_vec()))
            }
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                Err(anyhow::anyhow!("Consumer error: {}", e))
            }
        }
    }

    pub fn commit(&self) -> anyhow::Result<()> {
        self.consumer
            .commit_consumer_state(rdkafka::consumer::CommitMode::Sync)
            .context("Failed to commit offset")?;
        Ok(())
    }

    pub fn inner(&self) -> &StreamConsumer {
        &self.consumer
    }
}

// ============================================================================
// No-op stub (no "kafka" feature) — compiles without rdkafka
// ============================================================================

#[cfg(not(feature = "kafka"))]
/// No-op MessageConsumer stub — cannot poll, always errors on construction.
pub struct MessageConsumer;

#[cfg(not(feature = "kafka"))]
impl MessageConsumer {
    pub fn new(_config: &KafkaConfig) -> anyhow::Result<Self> {
        anyhow::bail!("Kafka feature not compiled in — rebuild with --features kafka")
    }

    pub async fn poll(&self, _timeout: Duration) -> anyhow::Result<Option<KafkaMessageEnvelope>> {
        anyhow::bail!("Kafka feature not compiled in")
    }

    pub async fn poll_raw(&self, _timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        anyhow::bail!("Kafka feature not compiled in")
    }

    pub fn commit(&self) -> anyhow::Result<()> {
        anyhow::bail!("Kafka feature not compiled in")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_creation_fails_when_disabled() {
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
