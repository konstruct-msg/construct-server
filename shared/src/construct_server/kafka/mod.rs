// Kafka module for reliable message delivery
//
// This module provides Kafka integration for persistent message storage and delivery.
// It supports multiple message types: Direct (Double Ratchet), MLS (groups), and S2S (federation).

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
