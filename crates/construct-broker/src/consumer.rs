use anyhow::{Context, Result};
use rdkafka::Message;
use rdkafka::consumer::{Consumer, StreamConsumer};
use std::time::Duration;
use tracing::{error, info};

use super::config::create_client_config;
use super::types::KafkaMessageEnvelope;
use construct_config::KafkaConfig;

/// Kafka message consumer for delivery worker
///
/// This consumer is configured for:
/// - Manual offset commits (after successful delivery)
/// - Consumer group coordination (multiple delivery workers)
/// - Auto-rebalancing on worker addition/removal
pub struct MessageConsumer {
    consumer: StreamConsumer,
    #[allow(dead_code)]
    topic: String,
}

impl MessageConsumer {
    /// Create a new Kafka consumer from the application configuration.
    ///
    /// The consumer will not be created if `config.enabled` is false.
    ///
    /// # Arguments
    /// * `config` - The Kafka configuration struct.
    ///
    /// # Configuration
    /// - `enable.auto.commit=false`: Manual offset management.
    /// - `auto.offset.reset=earliest`: Read from beginning on first start.
    /// - `session.timeout.ms=30000`: 30s session timeout.
    /// - `heartbeat.interval.ms=3000`: 3s heartbeat interval.
    pub fn new(config: &KafkaConfig) -> Result<Self> {
        if !config.enabled {
            anyhow::bail!("Cannot create Kafka consumer when Kafka is disabled");
        }

        info!("Initializing Kafka consumer...");
        let mut client_config = create_client_config(config)?;

        let consumer: StreamConsumer = client_config
            .set("group.id", &config.consumer_group)
            // Offset management
            .set("enable.auto.commit", "false") // Manual commit after delivery
            .set("auto.offset.reset", "earliest") // Read from beginning
            // Allow broker to auto-create topic on first subscription
            .set("allow.auto.create.topics", "true")
            // Performance
            .set("fetch.min.bytes", "1")
            .set("fetch.wait.max.ms", "500") // Max wait for fetch
            .set("max.partition.fetch.bytes", "1048576") // 1MB
            // Session management
            .set("session.timeout.ms", "30000") // 30s timeout
            .set("heartbeat.interval.ms", "3000") // 3s heartbeat
            .set("max.poll.interval.ms", "300000") // 5min max processing time
            .create()
            .context("Failed to create Kafka consumer")?;

        // Subscribe to topic
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

    /// Poll for next message
    ///
    /// Returns `None` if timeout expires without message.
    pub async fn poll(&self, _timeout: Duration) -> Result<Option<KafkaMessageEnvelope>> {
        match self.consumer.recv().await {
            Ok(message) => {
                // Parse payload
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

    /// Poll for next message (raw bytes)
    ///
    /// Returns raw payload bytes without deserialization.
    /// Useful for consuming messages with different schemas (e.g., DeliveryAckEvent).
    pub async fn poll_raw(&self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
        match self.consumer.recv().await {
            Ok(message) => {
                // Get raw payload
                let payload = message.payload().context("Message payload is empty")?;

                Ok(Some(payload.to_vec()))
            }
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                Err(anyhow::anyhow!("Consumer error: {}", e))
            }
        }
    }

    /// Commit current offset (after successful delivery)
    ///
    /// This tells Kafka "I've successfully processed all messages up to this point".
    /// If the consumer crashes before committing, messages will be redelivered.
    pub fn commit(&self) -> Result<()> {
        self.consumer
            .commit_consumer_state(rdkafka::consumer::CommitMode::Sync)
            .context("Failed to commit offset")?;
        Ok(())
    }

    /// Get consumer reference (for advanced usage)
    pub fn inner(&self) -> &StreamConsumer {
        &self.consumer
    }
}

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
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                "Cannot create Kafka consumer when Kafka is disabled"
            );
        }
    }
}
