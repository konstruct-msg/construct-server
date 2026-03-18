// ============================================================================
// MessageProducer — Kafka/Redpanda implementation
// Compiled only when the "kafka" feature is enabled.
// Without the feature, the no-op stub below is used instead.
// ============================================================================

#[cfg(feature = "kafka")]
use anyhow::{Context, Result};
#[cfg(feature = "kafka")]
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
#[cfg(feature = "kafka")]
use rdkafka::util::Timeout;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "kafka")]
use tracing::{error, info};

#[cfg(not(feature = "kafka"))]
use super::circuit_breaker::CircuitBreakerError;
#[cfg(feature = "kafka")]
use super::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
#[cfg(feature = "kafka")]
use super::config::create_client_config;
#[cfg(feature = "kafka")]
use super::metrics;
use super::types::{DeliveryAckEvent, KafkaMessageEnvelope};
use construct_config::KafkaConfig;

// ============================================================================
// Kafka implementation (feature = "kafka")
// ============================================================================

#[cfg(feature = "kafka")]
/// Kafka message producer for reliable message delivery
pub struct MessageProducer {
    /// The actual Kafka producer (None when disabled)
    producer: Option<Arc<FutureProducer>>,
    /// Circuit breaker for fault tolerance
    circuit_breaker: Arc<CircuitBreaker>,
    topic: String,
    enabled: bool,
}

#[cfg(feature = "kafka")]
impl MessageProducer {
    pub fn new(config: &KafkaConfig) -> anyhow::Result<Self> {
        let circuit_breaker_config = CircuitBreakerConfig {
            failure_threshold: 5,
            timeout: Duration::from_secs(3),
            reset_timeout: Duration::from_secs(30),
        };
        let circuit_breaker = Arc::new(CircuitBreaker::with_config(circuit_breaker_config));

        if !config.enabled {
            info!("Kafka/Redpanda producer disabled (KAFKA_ENABLED=false)");
            return Ok(Self {
                producer: None,
                circuit_breaker,
                topic: config.topic.clone(),
                enabled: false,
            });
        }

        info!("Initializing Kafka producer...");
        let mut client_config = create_client_config(config)?;

        let producer: FutureProducer = client_config
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
            "Kafka/Redpanda producer initialized successfully for topic '{}'",
            config.topic
        );

        Ok(Self {
            producer: Some(Arc::new(producer)),
            circuit_breaker,
            topic: config.topic.clone(),
            enabled: true,
        })
    }

    pub async fn send_message(
        &self,
        envelope: &KafkaMessageEnvelope,
    ) -> Result<(i32, i64), CircuitBreakerError<anyhow::Error>> {
        if !self.enabled {
            tracing::debug!(message_id = %envelope.message_id, "Kafka disabled — message skipped");
            return Ok((-1, -1));
        }
        self.circuit_breaker
            .call(async {
                self.send_message_internal(envelope)
                    .await
                    .map_err(|e| anyhow::anyhow!("Kafka send failed: {}", e))
            })
            .await
    }

    async fn send_message_internal(
        &self,
        envelope: &KafkaMessageEnvelope,
    ) -> anyhow::Result<(i32, i64)> {
        let producer = self
            .producer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Kafka producer not initialized"))?;

        if let Err(e) = envelope.validate() {
            return Err(e.context("Invalid message envelope"));
        }

        let payload =
            serde_json::to_vec(envelope).context("Failed to serialize message envelope")?;
        let key = envelope.recipient_id.as_bytes();
        let record = FutureRecord::to(&self.topic).key(key).payload(&payload);
        let start = std::time::Instant::now();

        match producer
            .send(record, Timeout::After(Duration::from_secs(2)))
            .await
        {
            Ok((partition, offset)) => {
                let latency = start.elapsed();
                metrics::KAFKA_PRODUCE_SUCCESS.inc();
                metrics::KAFKA_PRODUCE_LATENCY.observe(latency.as_secs_f64());
                info!(partition, offset, message_id = %envelope.message_id, latency_ms = latency.as_millis(), "Message persisted to Kafka/Redpanda");
                Ok((partition, offset))
            }
            Err((kafka_err, _)) => {
                metrics::KAFKA_PRODUCE_FAILURE.inc();
                error!(error = %kafka_err, message_id = %envelope.message_id, topic = %self.topic, "Failed to send message to Kafka/Redpanda");
                Err(anyhow::anyhow!("Kafka/Redpanda send failed: {}", kafka_err))
            }
        }
    }

    pub async fn send_delivery_ack(&self, event: &DeliveryAckEvent) -> anyhow::Result<(i32, i64)> {
        let producer = match &self.producer {
            Some(p) => p,
            None => return Ok((-1, -1)),
        };

        event.validate().context("Invalid delivery ACK event")?;
        let payload =
            serde_json::to_vec(event).context("Failed to serialize delivery ACK event")?;
        let key = event.message_hash.as_bytes();
        let ack_topic = format!("{}-delivery-ack", self.topic);
        let record = FutureRecord::to(&ack_topic).key(key).payload(&payload);
        let start = std::time::Instant::now();

        match producer
            .send(record, Timeout::After(Duration::from_secs(2)))
            .await
        {
            Ok((partition, offset)) => {
                let latency = start.elapsed();
                metrics::KAFKA_PRODUCE_SUCCESS.inc();
                metrics::KAFKA_PRODUCE_LATENCY.observe(latency.as_secs_f64());
                info!(partition, offset, message_hash = %event.message_hash, latency_ms = latency.as_millis(), "Delivery ACK persisted to Kafka/Redpanda");
                Ok((partition, offset))
            }
            Err((kafka_err, _)) => {
                metrics::KAFKA_PRODUCE_FAILURE.inc();
                error!(error = %kafka_err, message_hash = %event.message_hash, topic = %ack_topic, "Failed to send delivery ACK to Kafka/Redpanda");
                Err(anyhow::anyhow!(
                    "Kafka/Redpanda delivery ACK send failed: {}",
                    kafka_err
                ))
            }
        }
    }

    pub async fn flush(&self, timeout: Duration) -> anyhow::Result<()> {
        let producer = match &self.producer {
            Some(p) => p,
            None => return Ok(()),
        };
        info!("Flushing Kafka/Redpanda producer (timeout: {:?})", timeout);
        producer
            .flush(Timeout::After(timeout))
            .context("Failed to flush Kafka/Redpanda producer")?;
        info!("Kafka/Redpanda producer flushed successfully");
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

#[cfg(feature = "kafka")]
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

// ============================================================================
// No-op stub (no "kafka" feature) — compiles without rdkafka
// ============================================================================

#[cfg(not(feature = "kafka"))]
/// No-op MessageProducer stub used when the "kafka" feature is not enabled.
/// All send operations succeed immediately without any network I/O.
#[derive(Clone)]
pub struct MessageProducer {
    topic: String,
}

#[cfg(not(feature = "kafka"))]
impl MessageProducer {
    pub fn new(config: &KafkaConfig) -> anyhow::Result<Self> {
        Ok(Self {
            topic: config.topic.clone(),
        })
    }

    pub async fn send_message(
        &self,
        _envelope: &KafkaMessageEnvelope,
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
        let envelope = KafkaMessageEnvelope::new_direct_message(
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
