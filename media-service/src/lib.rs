// ============================================================================
// Media Service Library
// ============================================================================
//
// The production binary is `main.rs` (gRPC). This lib exposes shared modules
// for tests and any residual tooling. REST handlers always return 410 Gone.

pub mod cleanup;
pub mod config;
pub mod core;
pub mod handlers;
pub mod rate_limit;
pub mod types;
pub mod utils;

#[cfg(test)]
mod test_serde;
