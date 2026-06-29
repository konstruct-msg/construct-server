// Message envelope types for reliable message delivery.
//
// Supports multiple message types: Direct (Double Ratchet), MLS (groups), S2S (federation).
// Backend: Redis streams. The legacy Kafka/Redpanda transport (producer, consumer,
// circuit breaker) has been removed — this crate now only provides the envelope types.

pub mod types;

// Re-export commonly used types
pub use types::{DeliveryAckEvent, MessageEnvelope, MessageType};
