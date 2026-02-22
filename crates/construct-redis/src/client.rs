//! Redis client implementation with connection management

use crate::Result;
use redis::{aio::ConnectionManager, AsyncCommands};

/// Redis client with automatic reconnection
#[derive(Clone)]
pub struct RedisClient {
    conn: ConnectionManager,
}

impl RedisClient {
    /// Connect to Redis server
    ///
    /// Supports both redis:// and rediss:// (TLS) URLs
    pub async fn connect(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    /// Get connection manager (for advanced operations)
    pub fn connection(&self) -> &ConnectionManager {
        &self.conn
    }

    /// Clone the connection manager
    pub fn connection_mut(&mut self) -> &mut ConnectionManager {
        &mut self.conn
    }

    // ============================================================================
    // Key-Value Operations
    // ============================================================================

    /// GET - Get value by key
    pub async fn get<T: redis::FromRedisValue>(&mut self, key: &str) -> Result<Option<T>> {
        self.conn.get(key).await
    }

    /// SET - Set key to value
    pub async fn set<V>(&mut self, key: &str, value: V) -> Result<()>
    where
        V: redis::ToRedisArgs + redis::ToSingleRedisArg + Send + Sync,
    {
        self.conn.set(key, value).await
    }

    /// SETEX - Set key with expiry in seconds
    pub async fn set_ex<V>(&mut self, key: &str, value: V, seconds: u64) -> Result<()>
    where
        V: redis::ToRedisArgs + redis::ToSingleRedisArg + Send + Sync,
    {
        self.conn.set_ex(key, value, seconds).await
    }

    /// DEL - Delete one or more keys
    pub async fn del<K>(&mut self, keys: K) -> Result<i64>
    where
        K: redis::ToRedisArgs + Send + Sync,
    {
        self.conn.del(keys).await
    }

    /// EXISTS - Check if key exists
    pub async fn exists(&mut self, key: &str) -> Result<bool> {
        self.conn.exists(key).await
    }

    /// EXPIRE - Set expiry time in seconds
    pub async fn expire(&mut self, key: &str, seconds: i64) -> Result<bool> {
        self.conn.expire(key, seconds).await
    }

    /// TTL - Get time to live in seconds
    pub async fn ttl(&mut self, key: &str) -> Result<i64> {
        self.conn.ttl(key).await
    }

    // ============================================================================
    // Atomic Operations
    // ============================================================================

    /// INCR - Increment integer value
    pub async fn incr(&mut self, key: &str) -> Result<i64> {
        self.conn.incr(key, 1).await
    }

    /// INCRBY - Increment by specific amount
    pub async fn incr_by(&mut self, key: &str, delta: i64) -> Result<i64> {
        self.conn.incr(key, delta).await
    }

    /// DECR - Decrement integer value
    pub async fn decr(&mut self, key: &str) -> Result<i64> {
        self.conn.decr(key, 1).await
    }

    // ============================================================================
    // List Operations
    // ============================================================================

    /// LPUSH - Push to head of list
    pub async fn lpush<V>(&mut self, key: &str, value: V) -> Result<i64>
    where
        V: redis::ToRedisArgs + Send + Sync,
    {
        self.conn.lpush(key, value).await
    }

    /// RPUSH - Push to tail of list
    pub async fn rpush<V>(&mut self, key: &str, value: V) -> Result<i64>
    where
        V: redis::ToRedisArgs + Send + Sync,
    {
        self.conn.rpush(key, value).await
    }

    /// LPOP - Pop from head of list
    pub async fn lpop<T: redis::FromRedisValue>(&mut self, key: &str) -> Result<Option<T>> {
        self.conn.lpop(key, None).await
    }

    /// LLEN - Get list length
    pub async fn llen(&mut self, key: &str) -> Result<i64> {
        self.conn.llen(key).await
    }

    // ============================================================================
    // Set Operations
    // ============================================================================

    /// SADD - Add member to set
    pub async fn sadd<V>(&mut self, key: &str, member: V) -> Result<i64>
    where
        V: redis::ToRedisArgs + Send + Sync,
    {
        self.conn.sadd(key, member).await
    }

    /// SISMEMBER - Check if member exists in set
    pub async fn sismember<V>(&mut self, key: &str, member: V) -> Result<bool>
    where
        V: redis::ToRedisArgs + redis::ToSingleRedisArg + Send + Sync,
    {
        self.conn.sismember(key, member).await
    }

    /// SREM - Remove member from set
    pub async fn srem<V>(&mut self, key: &str, member: V) -> Result<i64>
    where
        V: redis::ToRedisArgs + Send + Sync,
    {
        self.conn.srem(key, member).await
    }

    // ============================================================================
    // Lua Scripts
    // ============================================================================

    /// Execute Lua script
    /// Note: For complex scripts, consider using redis::Script directly
    pub fn create_script(code: &str) -> redis::Script {
        redis::Script::new(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Redis instance
    // Run with: docker run -d -p 6379:6379 redis:7

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_basic_operations() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;

        // SET/GET
        client.set("test_key", "test_value").await?;
        let value: Option<String> = client.get("test_key").await?;
        assert_eq!(value, Some("test_value".to_string()));

        // DEL
        client.del("test_key").await?;
        let value: Option<String> = client.get("test_key").await?;
        assert_eq!(value, None);

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_expiry() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;

        // SET with expiry
        client.set_ex("expire_test", "value", 10).await?;
        let ttl = client.ttl("expire_test").await?;
        assert!(ttl > 0 && ttl <= 10);

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_atomic_ops() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;

        // INCR
        let count1 = client.incr("counter").await?;
        let count2 = client.incr("counter").await?;
        assert_eq!(count2, count1 + 1);

        client.del("counter").await?;

        Ok(())
    }
}
