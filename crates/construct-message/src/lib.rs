// Message broker client for reliable message delivery.
//
// Supports multiple message types: Direct (Double Ratchet), MLS (groups), S2S (federation).
// Backend: Redis streams. The legacy Kafka/Redpanda transport has been removed —
// `MessageProducer` / `MessageConsumer` are no-op stubs kept for API compatibility.

pub mod circuit_breaker;
pub mod consumer;
pub mod producer;
pub mod types;

// Re-export commonly used types
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
pub use consumer::MessageConsumer;
pub use producer::MessageProducer;
pub use types::{DeliveryAckEvent, MessageEnvelope, MessageType};
