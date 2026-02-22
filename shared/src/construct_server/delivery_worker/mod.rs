// ============================================================================
// Delivery Worker Modules
// ============================================================================
//
// Modular delivery worker implementing Kafka as Single Source of Truth
// with Redis Streams for efficient message delivery.
//
// ARCHITECTURE: Hybrid Approach (Kafka + Redis)
// ============================================================================
//
// Modules:
// - state.rs      - WorkerState and shared state
// - retry.rs      - Redis retry logic with auto-reconnection
// - redis_streams.rs - Redis Streams operations (XADD, XREADGROUP)
// - deduplication.rs - Multi-layer message deduplication
// - processor.rs  - Main message processing with ProcessResult
//
// Key Components:
// - ProcessResult enum controls Kafka offset commit behavior
// - Only commit offset for ONLINE users (Success/Skipped)
// - DO NOT commit for OFFLINE users (UserOffline)
//
// Entry point: bin/delivery_worker.rs uses this module
//
// ============================================================================

pub mod deduplication;
pub mod processor;
pub mod redis_streams;
pub mod retry;
pub mod state;

// Re-export commonly used types and functions
pub use processor::{ProcessResult, process_kafka_message};
pub use state::WorkerState;
