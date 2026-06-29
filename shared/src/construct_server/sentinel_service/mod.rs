// Sentinel business logic re-exported for embedding in messaging-service.
// The core implementation lives here; the gRPC transport lives in messaging-service.

pub mod core;

pub use core::{ProtectionStats, SendPermission, SentinelCore, TrustLevel};
