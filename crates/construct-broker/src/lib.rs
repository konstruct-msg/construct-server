// Message broker client for reliable message delivery (Redpanda/Kafka compatible).
//
// Supports multiple message types: Direct (Double Ratchet), MLS (groups), S2S (federation).
// Backend: Redpanda (Kafka-compatible API).
//
// Feature flags:
//   kafka — enables the rdkafka transport. Without it, MessageProducer and
//           MessageConsumer compile as no-op stubs (no network I/O, no rdkafka dep).

pub mod circuit_breaker;
pub mod config;
pub mod consumer;
pub mod metrics;
pub mod producer;
pub mod types;

// Re-export commonly used types
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
#[cfg(feature = "kafka")]
pub use config::create_client_config;
pub use consumer::MessageConsumer;
pub use producer::MessageProducer;
pub use types::{DeliveryAckEvent, KafkaMessageEnvelope, MessageType};
