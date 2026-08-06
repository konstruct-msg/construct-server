// ============================================================================
// Media Service Library
// ============================================================================
//
// Production binary is `main.rs` (gRPC only). This lib re-exports modules for
// unit tests. Client media is MediaService gRPC — no REST upload/download.

pub mod config;
pub mod core;
pub mod rate_limit;
pub mod utils;
