// ============================================================================
// Pending Messages - 2-Phase Commit Protocol
// ============================================================================
//
// This module implements the pending message storage for the 2-phase commit
// protocol, eliminating message loss on network failures.
//
// PROBLEM: Network failure after Kafka write but before client receives response
// → Client thinks message not sent → Retry → Duplicate
//
// SOLUTION: 2-Phase Commit with idempotent Phase 1
//
// Phase 1 (PREPARE): Client sends message with temp_id
//   - Server checks: temp_id exists in Redis? → Return existing result (idempotent)
//   - Server stores PENDING state → Writes to Kafka → Returns success
//   - Network failure? Client retries with SAME temp_id → Gets same result
//
// Phase 2 (COMMIT): Client confirms receipt (fire-and-forget)
//   - Server updates PENDING → CONFIRMED
//   - Network failure? Auto-cleanup worker commits after 5 minutes
//
// ============================================================================

mod storage;
mod types;

pub use storage::{PendingMessageMetrics, PendingMessageStorage};
pub use types::{MessageStatus, PendingMessageData};
