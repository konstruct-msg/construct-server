// Sentinel service business logic is in crates/construct-sentinel-service.
// This module re-exports it so existing call sites
// (`construct_server_shared::sentinel_service::SentinelCore`) keep working
// unchanged. The gRPC transport lives in messaging-service.

pub use construct_sentinel_service::{ProtectionStats, SendPermission, SentinelCore, TrustLevel};
