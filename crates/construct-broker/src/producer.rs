use anyhow::{Context, Result};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use rdkafka::util::Timeout;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use super::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
use super::config::create_client_config;
use super::metrics;
use super::types::{DeliveryAckEvent, KafkaMessageEnvelope};
use construct_config::KafkaConfig;

/// Kafka message producer for reliable message delivery
///
/// This producer is configured for:
/// - At-least-once delivery guarantees
/// - Idempotent writes (no duplicates within producer session)
/// - Compression (snappy)
/// - Low latency (10ms linger)
/// - Circuit breaker protection (prevents cascading failures)
pub struct MessageProducer {
    /// The actual Kafka producer (None when disabled)
    producer: Option<Arc<FutureProducer>>,
    /// Circuit breaker for fault tolerance
    circuit_breaker: Arc<CircuitBreaker>,
    topic: String,
    enabled: bool,
}

impl MessageProducer {
    /// Create a new Kafka producer from the application configuration.
    ///
    /// # Arguments
    /// * `config` - The Kafka configuration struct.
    ///
    /// # Configuration
    /// - `acks=all`: Wait for all in-sync replicas to acknowledge.
    /// - `enable.idempotence=true`: Prevent duplicate writes.
    /// - `retries=2147483647`: Retry indefinitely on transient errors.
    /// - `compression.type=snappy`: Optimized compression.
    /// - `linger.ms=10`: Small batching window for low latency.
    /// - Circuit breaker: 5 failures → open, 3s timeout, 30s reset
    pub fn new(config: &KafkaConfig) -> Result<Self> {
        // Create circuit breaker (always, even when Kafka disabled)
        let circuit_breaker_config = CircuitBreakerConfig {
            failure_threshold: 5,
            timeout: Duration::from_secs(3),
            reset_timeout: Duration::from_secs(30),
        };
        let circuit_breaker = Arc::new(CircuitBreaker::with_config(circuit_breaker_config));

        if !config.enabled {
            info!("Kafka/Redpanda producer disabled (KAFKA_ENABLED=false)");
            // Don't create any producer when disabled - avoid connection attempts entirely
            return Ok(Self {
                producer: None,
                circuit_breaker,
                topic: config.topic.clone(),
                enabled: false,
            });
        }

        info!("Initializing Kafka producer...");
        let mut client_config = create_client_config(config)?;

        // Producer-specific settings
        let producer: FutureProducer = client_config
            // Reliability settings
            .set("acks", &config.producer_acks)
            .set(
                "enable.idempotence",
                if config.producer_enable_idempotence {
                    "true"
                } else {
                    "false"
                },
            )
            .set(
                "max.in.flight.requests.per.connection",
                config.producer_max_in_flight.to_string(),
            )
            .set("retries", config.producer_retries.to_string())
            .set("compression.type", &config.producer_compression)
            .set("linger.ms", config.producer_linger_ms.to_string())
            .set("batch.size", config.producer_batch_size.to_string())
            .set(
                "request.timeout.ms",
                config.producer_request_timeout_ms.to_string(),
            )
            .set(
                "delivery.timeout.ms",
                config.producer_delivery_timeout_ms.to_string(),
            )
            .create()
            .context("Failed to create Kafka producer")?;

        info!(
            "Kafka/Redpanda producer initialized successfully for topic '{}' with circuit breaker",
            config.topic
        );

        Ok(Self {
            producer: Some(Arc::new(producer)),
            circuit_breaker,
            topic: config.topic.clone(),
            enabled: true,
        })
    }

    /// Send a message to Kafka with circuit breaker protection
    ///
    /// This is a blocking async operation that waits for Kafka acknowledgment.
    /// Circuit breaker protects against cascading failures:
    /// - If Kafka is slow/down, circuit opens after 5 failures
    /// - Subsequent requests fail fast (no blocking)
    /// - Automatically recovers when Kafka is back
    ///
    /// # Arguments
    /// * `envelope` - Message envelope to send
    ///
    /// # Returns
    /// * `Ok((partition, offset))` - Successfully written to Kafka
    /// * `Err(CircuitBreakerError::Open)` - Circuit is open, Kafka unavailable
    /// * `Err(CircuitBreakerError::Timeout)` - Request timed out (3s)
    /// * `Err(CircuitBreakerError::Inner)` - Kafka error
    pub async fn send_message(
        &self,
        envelope: &KafkaMessageEnvelope,
    ) -> Result<(i32, i64), CircuitBreakerError<anyhow::Error>> {
        // Skip if Kafka/Redpanda disabled
        if !self.enabled {
            tracing::debug!(
                message_id = %envelope.message_id,
                "Kafka/Redpanda disabled - message NOT sent (dummy response)"
            );
            return Ok((-1, -1)); // Dummy partition/offset
        }

        // Execute with circuit breaker protection
        self.circuit_breaker
            .call(async {
                self.send_message_internal(envelope)
                    .await
                    .map_err(|e| anyhow::anyhow!("Kafka send failed: {}", e))
            })
            .await
    }

    /// Internal send implementation (wrapped by circuit breaker)
    async fn send_message_internal(&self, envelope: &KafkaMessageEnvelope) -> Result<(i32, i64)> {
        let producer = self
            .producer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Kafka producer not initialized"))?;

        // Validate envelope before sending
        if let Err(e) = envelope.validate() {
            tracing::warn!(
                message_id = %envelope.message_id,
                sender_id_empty = envelope.sender_id.is_empty(),
                recipient_id_empty = envelope.recipient_id.is_empty(),
                encrypted_payload_empty = envelope.encrypted_payload.is_empty(),
                content_hash_empty = envelope.content_hash.is_empty(),
                error = %e,
                "Kafka envelope validation failed"
            );
            return Err(e.context("Invalid message envelope"));
        }

        // Serialize to JSON
        let payload =
            serde_json::to_vec(envelope).context("Failed to serialize message envelope")?;

        // Partition key: recipient_id (ensures ordering per user/group)
        let key = envelope.recipient_id.as_bytes();

        // Create Kafka record
        let record = FutureRecord::to(&self.topic).key(key).payload(&payload);

        // Send with timeout (2 seconds for async feedback)
        let start = std::time::Instant::now();

        match producer
            .send(record, Timeout::After(Duration::from_secs(2)))
            .await
        {
            Ok((partition, offset)) => {
                let latency = start.elapsed();

                // Update metrics
                metrics::KAFKA_PRODUCE_SUCCESS.inc();
                metrics::KAFKA_PRODUCE_LATENCY.observe(latency.as_secs_f64());

                info!(
                    partition = partition,
                    offset = offset,
                    message_id = %envelope.message_id,
                    latency_ms = latency.as_millis(),
                    "Message persisted to Kafka/Redpanda"
                );

                Ok((partition, offset))
            }
            Err((kafka_err, _)) => {
                let latency = start.elapsed();

                // Update metrics
                metrics::KAFKA_PRODUCE_FAILURE.inc();

                error!(
                    error = %kafka_err,
                    message_id = %envelope.message_id,
                    topic = %self.topic,
                    latency_ms = latency.as_millis(),
                    "Failed to send message to Kafka/Redpanda"
                );

                Err(anyhow::anyhow!("Kafka/Redpanda send failed: {}", kafka_err))
            }
        }
    }

    /// Check if Kafka is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get topic name
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Send a delivery ACK event to Kafka (Solution 1D - Privacy-First)
    ///
    /// **SECURITY**: This method sends DeliveryAckEvent with ONLY hashed IDs.
    /// - message_hash: HMAC-SHA256(message_id)
    /// - sender_id_hash: HMAC-SHA256(sender_id)
    /// - recipient_id_hash: HMAC-SHA256(recipient_id)
    ///
    /// Kafka logs contain NO plaintext user IDs, preventing correlation attacks.
    ///
    /// # Arguments
    /// * `event` - DeliveryAckEvent with pre-hashed IDs
    ///
    /// # Returns
    /// * `Ok((partition, offset))` - Successfully written to Kafka
    /// * `Err(anyhow::Error)` - Failed to write
    pub async fn send_delivery_ack(&self, event: &DeliveryAckEvent) -> Result<(i32, i64)> {
        // Skip if Kafka/Redpanda disabled
        let producer = match &self.producer {
            Some(p) => p,
            None => {
                return Ok((-1, -1)); // Dummy partition/offset
            }
        };

        // Validate event before sending (checks hash lengths, etc.)
        event.validate().context("Invalid delivery ACK event")?;

        // Serialize to JSON
        let payload =
            serde_json::to_vec(event).context("Failed to serialize delivery ACK event")?;

        // Partition key: message_hash (ensures same partition for retries)
        // NOTE: Using message_hash (not user ID hash) for partitioning
        // This distributes load evenly and prevents hot partitions
        let key = event.message_hash.as_bytes();

        // Topic for delivery ACKs (separate from messages for ACL isolation)
        let ack_topic = format!("{}-delivery-ack", self.topic);

        // Create Kafka record
        let record = FutureRecord::to(&ack_topic).key(key).payload(&payload);

        // Send with timeout
        let start = std::time::Instant::now();

        match producer
            .send(record, Timeout::After(Duration::from_secs(2)))
            .await
        {
            Ok((partition, offset)) => {
                let latency = start.elapsed();

                // Update metrics
                metrics::KAFKA_PRODUCE_SUCCESS.inc();
                metrics::KAFKA_PRODUCE_LATENCY.observe(latency.as_secs_f64());

                // SECURITY: Log ONLY hashes, NEVER plaintext IDs
                info!(
                    partition = partition,
                    offset = offset,
                    message_hash = %event.message_hash,
                    latency_ms = latency.as_millis(),
                    "Delivery ACK event persisted to Kafka/Redpanda"
                );

                Ok((partition, offset))
            }
            Err((kafka_err, _)) => {
                let latency = start.elapsed();

                // Update metrics
                metrics::KAFKA_PRODUCE_FAILURE.inc();

                // SECURITY: Log ONLY hash, NEVER plaintext message_id
                error!(
                    error = %kafka_err,
                    message_hash = %event.message_hash,
                    topic = %ack_topic,
                    latency_ms = latency.as_millis(),
                    "Failed to send delivery ACK event to Kafka/Redpanda"
                );

                Err(anyhow::anyhow!(
                    "Kafka/Redpanda delivery ACK send failed: {}",
                    kafka_err
                ))
            }
        }
    }

    /// Flush pending messages (for graceful shutdown)
    ///
    /// This waits for all in-flight messages to be acknowledged.
    /// Should be called before application shutdown.
    pub async fn flush(&self, timeout: Duration) -> Result<()> {
        let producer = match &self.producer {
            Some(p) => p,
            None => return Ok(()), // Nothing to flush when disabled
        };

        info!("Flushing Kafka/Redpanda producer (timeout: {:?})", timeout);

        producer
            .flush(Timeout::After(timeout))
            .context("Failed to flush Kafka/Redpanda producer")?;

        info!("Kafka/Redpanda producer flushed successfully");
        Ok(())
    }
}

// Implement Clone manually to avoid cloning the producer (Arc handles it)
impl Clone for MessageProducer {
    fn clone(&self) -> Self {
        Self {
            producer: self.producer.as_ref().map(Arc::clone),
            circuit_breaker: Arc::clone(&self.circuit_breaker),
            topic: self.topic.clone(),
            enabled: self.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_config::KafkaConfig;

    #[test]
    fn test_disabled_producer_creation() {
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
            producer_compression: String::from("gzip"),
            producer_acks: String::from("all"),
            producer_linger_ms: 5,
            producer_batch_size: 1024,
            producer_max_in_flight: 10,
            producer_retries: 3,
            producer_request_timeout_ms: 10000,
            producer_delivery_timeout_ms: 30000,
            producer_enable_idempotence: true,
        };
        let producer = MessageProducer::new(&config);

        assert!(producer.is_ok());
        assert!(!producer.unwrap().is_enabled());
    }

    #[tokio::test]
    async fn test_disabled_producer_send() {
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
            producer_compression: String::from("gzip"),
            producer_acks: String::from("all"),
            producer_linger_ms: 5,
            producer_batch_size: 1024,
            producer_max_in_flight: 10,
            producer_retries: 3,
            producer_request_timeout_ms: 10000,
            producer_delivery_timeout_ms: 30000,
            producer_enable_idempotence: true,
        };
        let producer = MessageProducer::new(&config).unwrap();

        let envelope = KafkaMessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "user-456".to_string(),
            "user-789".to_string(),
            vec![0u8; 32],
            42,
            "encrypted".to_string(),
            "hash123".to_string(),
        );

        // Should succeed with dummy values
        let result = producer.send_message(&envelope).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (-1, -1));
    }
}
