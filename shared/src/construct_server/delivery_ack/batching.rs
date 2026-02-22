// ============================================================================
// ACK Batching - Timing Correlation Attack Mitigation
// ============================================================================
//
// **SECURITY PROBLEM**: Without batching, an attacker can correlate:
// - Time when Alice sends message → Kafka "message sent" event
// - Time when Bob receives message → Kafka "delivered" ACK event
// - Correlation reveals: Alice and Bob are communicating
//
// **SOLUTION**: Buffer ACK events for N seconds, then send in randomized order.
// - Attacker sees batches of ACKs, not individual timing
// - Much harder to correlate specific sender-recipient pairs
//
// **TRADEOFF**: Adds 0-5 second delay to "delivered" ACK notification
// - Acceptable for most use cases (not real-time critical)
// - Configurable via DELIVERY_ACK_BATCH_BUFFER_SECS
//
// ============================================================================

use anyhow::Result;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

use crate::kafka::producer::MessageProducer;
use crate::kafka::types::DeliveryAckEvent;

/// ACK Batcher - buffers and randomizes delivery ACK events
///
/// **Privacy protection**: Prevents timing correlation attacks
pub struct AckBatcher {
    /// Kafka producer for sending batched ACKs
    producer: Arc<MessageProducer>,

    /// Buffered ACK events (protected by mutex)
    buffer: Arc<Mutex<Vec<DeliveryAckEvent>>>,

    /// Buffer duration in seconds (default: 5)
    buffer_duration: Duration,

    /// Whether batching is enabled (false = passthrough mode)
    enabled: bool,
}

impl AckBatcher {
    /// Create a new ACK batcher
    ///
    /// # Arguments
    /// * `producer` - Kafka producer for sending ACKs
    /// * `buffer_secs` - How long to buffer ACKs before sending (0-60 seconds)
    /// * `enabled` - Whether to enable batching (false = immediate send)
    pub fn new(producer: Arc<MessageProducer>, buffer_secs: u64, enabled: bool) -> Self {
        Self {
            producer,
            buffer: Arc::new(Mutex::new(Vec::new())),
            buffer_duration: Duration::from_secs(buffer_secs),
            enabled,
        }
    }

    /// Add an ACK event to the buffer
    ///
    /// If batching is disabled, sends immediately.
    /// If batching is enabled, adds to buffer for later batch send.
    pub async fn enqueue_ack(&self, event: DeliveryAckEvent) -> Result<()> {
        if !self.enabled {
            // Passthrough mode: send immediately
            self.producer.send_delivery_ack(&event).await?;
            return Ok(());
        }

        // Add to buffer
        let mut buffer = self.buffer.lock().await;
        buffer.push(event);

        tracing::trace!(
            buffer_size = buffer.len(),
            "ACK event added to batch buffer"
        );

        Ok(())
    }

    /// Flush the buffer: send all buffered ACKs in randomized order
    ///
    /// This is called periodically by the background task.
    /// Also called manually during shutdown.
    pub async fn flush(&self) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Nothing to flush in passthrough mode
        }

        // Take all events from buffer
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(()); // Nothing to flush
        }

        let mut events: Vec<DeliveryAckEvent> = buffer.drain(..).collect();
        drop(buffer); // Release lock early

        let batch_size = events.len();

        // PRIVACY: Randomize order to prevent timing correlation
        // Use StdRng with time-based seed for Send compatibility
        // SECURITY: Handle system time errors gracefully
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "System time is before UNIX_EPOCH, using fallback timestamp");
                std::time::Duration::from_secs(1577836800) // 2020-01-01 fallback
            })
            .as_nanos() as u64;
        let mut rng = StdRng::seed_from_u64(seed);
        events.shuffle(&mut rng);

        tracing::debug!(
            batch_size = batch_size,
            "Flushing ACK batch in randomized order"
        );

        // Send all events (continue on errors, log failures)
        let mut success_count = 0;
        let mut failure_count = 0;

        for event in events {
            match self.producer.send_delivery_ack(&event).await {
                Ok(_) => success_count += 1,
                Err(e) => {
                    failure_count += 1;
                    tracing::error!(
                        error = %e,
                        message_hash = %event.message_hash,
                        "Failed to send batched ACK event"
                    );
                }
            }
        }

        if failure_count > 0 {
            tracing::warn!(
                batch_size = batch_size,
                success_count = success_count,
                failure_count = failure_count,
                "ACK batch completed with some failures"
            );
        } else {
            tracing::info!(batch_size = batch_size, "ACK batch flushed successfully");
        }

        Ok(())
    }

    /// Start the background flush task
    ///
    /// This task runs periodically (every buffer_duration seconds)
    /// and flushes any buffered ACK events.
    ///
    /// # Returns
    /// A tokio task handle that can be used to cancel the task
    pub fn start_background_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if !self.enabled {
                tracing::info!("ACK batching disabled, background task not started");
                return;
            }

            let mut ticker = interval(self.buffer_duration);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            tracing::info!(
                buffer_duration_secs = self.buffer_duration.as_secs(),
                "ACK batcher background task started"
            );

            loop {
                ticker.tick().await;

                if let Err(e) = self.flush().await {
                    tracing::error!(error = %e, "ACK batch flush failed");
                }
            }
        })
    }

    /// Get current buffer size (for metrics/monitoring)
    pub async fn buffer_size(&self) -> usize {
        let buffer = self.buffer.lock().await;
        buffer.len()
    }

    /// Check if batching is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kafka::types::DeliveryAckEvent;
    use construct_config::KafkaConfig;

    #[tokio::test]
    async fn test_passthrough_mode() {
        let config = KafkaConfig {
            enabled: false,
            brokers: "localhost:9092".to_string(),
            topic: "test".to_string(),
            consumer_group: "test".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            producer_compression: "gzip".to_string(),
            producer_acks: "all".to_string(),
            producer_linger_ms: 5,
            producer_batch_size: 1024,
            producer_max_in_flight: 10,
            producer_retries: 3,
            producer_request_timeout_ms: 10000,
            producer_delivery_timeout_ms: 30000,
            producer_enable_idempotence: true,
        };

        let producer = Arc::new(MessageProducer::new(&config).unwrap());
        let batcher = AckBatcher::new(producer, 5, false); // Disabled

        let event = DeliveryAckEvent::new(
            "msg-123".to_string(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );

        // Should send immediately without buffering
        let result = batcher.enqueue_ack(event).await;
        assert!(result.is_ok());

        // Buffer should remain empty
        assert_eq!(batcher.buffer_size().await, 0);
    }

    #[tokio::test]
    async fn test_buffering_mode() {
        let config = KafkaConfig {
            enabled: false,
            brokers: "localhost:9092".to_string(),
            topic: "test".to_string(),
            consumer_group: "test".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            producer_compression: "gzip".to_string(),
            producer_acks: "all".to_string(),
            producer_linger_ms: 5,
            producer_batch_size: 1024,
            producer_max_in_flight: 10,
            producer_retries: 3,
            producer_request_timeout_ms: 10000,
            producer_delivery_timeout_ms: 30000,
            producer_enable_idempotence: true,
        };

        let producer = Arc::new(MessageProducer::new(&config).unwrap());
        let batcher = AckBatcher::new(producer, 5, true); // Enabled

        // Add 3 events
        for i in 0..3 {
            let event = DeliveryAckEvent::new(
                format!("msg-{}", i),
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
            );
            batcher.enqueue_ack(event).await.unwrap();
        }

        // Buffer should contain 3 events
        assert_eq!(batcher.buffer_size().await, 3);

        // Flush
        batcher.flush().await.unwrap();

        // Buffer should be empty
        assert_eq!(batcher.buffer_size().await, 0);
    }
}
