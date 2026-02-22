//! # Construct Redis
//!
//! Low-level Redis client for Construct secure messaging server.
//!
//! ## Design Principles
//!
//! - **No business logic** - Pure infrastructure layer
//! - **No dependencies** on other construct-* crates  
//! - **Generic operations** - Can be used by any service
//! - **Type-safe** - Leverages Rust's type system
//!
//! ## Features
//!
//! - Connection management with automatic reconnection
//! - Key-value operations  
//! - Expiry and TTL management
//! - Atomic operations (INCR, Lua scripts)
//! - Redis Streams
//! - Pub/Sub
//!
//! ## Example
//!
//! ```rust,no_run
//! use construct_redis::RedisClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = RedisClient::connect("redis://localhost:6379").await?;
//!     
//!     // Set with expiry
//!     client.set_ex("key", "value", 3600).await?;
//!     
//!     // Get
//!     let value: Option<String> = client.get("key").await?;
//!     
//!     Ok(())
//! }
//! ```

mod client;
mod streams;

pub use client::RedisClient;
pub use streams::{StreamEntry, StreamEntryBinary, StreamReadOptions};

// Re-export commonly used types
pub use redis::RedisError;

/// Result type for Redis operations
pub type Result<T> = std::result::Result<T, RedisError>;
