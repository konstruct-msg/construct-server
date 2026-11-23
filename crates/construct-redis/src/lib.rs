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
//!     let mut client = RedisClient::connect("redis://localhost:6379").await?;
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
pub mod connect;
pub use connect::{connect as connect_manager, connection_config, manager_for};
mod streams;

pub use client::RedisClient;
pub use streams::{StreamEntry, StreamEntryBinary, StreamReadBinary, StreamReadOptions};

// Re-export commonly used types
pub use redis::RedisError;

/// Result type for Redis operations
pub type Result<T> = std::result::Result<T, RedisError>;

#[cfg(test)]
mod test_support {
    use crate::RedisClient;

    /// The Redis the caller chose, so a run against a throwaway instance stays there.
    pub(crate) async fn client() -> RedisClient {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
        RedisClient::connect(&url).await.expect("Redis required")
    }

    /// A key no other test, run or developer is using.
    pub(crate) fn key(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        format!("test:construct-redis:{name}:{}:{nanos}", std::process::id())
    }
}
