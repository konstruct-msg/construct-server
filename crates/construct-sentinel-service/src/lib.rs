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

pub use core::{ProtectionStats, SendPermission, SentinelCore, TrustLevel};
