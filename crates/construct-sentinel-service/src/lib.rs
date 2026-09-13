// ============================================================================
// construct-sentinel-service
// ============================================================================
//
// Sentinel service business logic: trust-level scoring, rate limiting,
// device blocks, spam reports, admin ban/flag/clear.
//
// Extracted from shared/`construct_server::sentinel_service::core` for
// reuse from the messaging-service binary (in-process enforcement) and
// the thin shared proto adapter.
//
// This crate intentionally has NO dependency on generated proto types —
// the gRPC transport layer lives in messaging-service.
// ============================================================================

pub mod core;

pub use core::{ProtectionStats, QuotaOutcome, SendPermission, SentinelCore, TrustLevel};
// Moved to construct-rate-limit (2026-09-13) so the sealed-sender door can reach it
// without depending on this service crate. Re-exported so callers here are unchanged.
pub use construct_rate_limit::{BreakerState, DegradedLimiter};
