// Message broker client for reliable message delivery (Redpanda/Kafka compatible).
//
// Supports multiple message types: Direct (Double Ratchet), MLS (groups), S2S (federation).
// Backend: Redpanda (Kafka-compatible API).

pub mod circuit_breaker;
pub mod config;
pub mod consumer;
pub mod metrics;
pub mod producer;
pub mod types;

// Re-export commonly used types
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
pub use config::create_client_config;
pub use consumer::MessageConsumer;
pub use producer::MessageProducer;
pub use types::{DeliveryAckEvent, KafkaMessageEnvelope, MessageType};
