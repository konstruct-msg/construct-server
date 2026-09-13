// ============================================================================
// Redis Connection and Basic Operations
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization

use anyhow::Result;
use construct_config::Config;

/// Redis connection manager wrapper
#[allow(dead_code)]
pub struct RedisConnection {
    pub(crate) client: redis::aio::ConnectionManager,
}

impl RedisConnection {
    #[allow(dead_code)]
    pub(crate) async fn new(config: &Config) -> Result<Self> {
        tracing::debug!("Opening Redis client...");

        // Parse Redis URL to check if TLS is required
        let is_tls = config.redis_url.starts_with("rediss://");
        if is_tls {
            tracing::info!("Redis TLS enabled (rediss://)");
        } else {
            tracing::info!("Redis TLS not enabled (redis://)");
        }

        let client = redis::Client::open(config.redis_url.clone())
            .map_err(|e| anyhow::anyhow!("Failed to parse Redis URL: {}", e))?;

        tracing::debug!("Getting Redis connection manager...");
        // This is the connection the sealed-sender door runs on, and its circuit breaker
        // trips on errors — so the response timeout in `construct_redis::connect` is what
        // turns a hung Redis into a failure it can see instead of a hang it cannot.
        let conn = construct_redis::manager_for(client)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

        Ok(Self { client: conn })
    }

    #[allow(dead_code)]
    pub(crate) async fn ping(&mut self) -> Result<()> {
        let _: () = redis::cmd("PING").query_async(&mut self.client).await?;
        Ok(())
    }
}
