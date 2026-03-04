// ============================================================================
// Cache Operations
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_config::SECONDS_PER_HOUR;
use construct_crypto::UploadableKeyBundle;
use construct_redis::RedisClient;

pub(crate) struct CacheManager<'a> {
    client: &'a mut RedisClient,
}

impl<'a> CacheManager<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    pub(crate) async fn cache_key_bundle(
        &mut self,
        user_id: &str,
        bundle: &UploadableKeyBundle,
        ttl_hours: i64,
    ) -> Result<()> {
        let key = format!("key_bundle:{}", user_id);
        let bundle_json = serde_json::to_string(bundle)
            .map_err(|e| anyhow::anyhow!("Failed to serialize bundle: {}", e))?;
        let ttl_seconds = ttl_hours * SECONDS_PER_HOUR;
        let _: () = self
            .client
            .set_ex(&key, bundle_json, ttl_seconds as u64)
            .await?;
        tracing::debug!(user_id = %user_id, ttl_hours = ttl_hours, "Cached key bundle");
        Ok(())
    }

    pub(crate) async fn get_cached_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<UploadableKeyBundle>> {
        let key = format!("key_bundle:{}", user_id);
        let bundle_json: Option<String> = self.client.get(&key).await?;

        match bundle_json {
            Some(json) => {
                let bundle: UploadableKeyBundle = serde_json::from_str(&json)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize bundle: {}", e))?;
                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }

    pub(crate) async fn invalidate_key_bundle_cache(&mut self, user_id: &str) -> Result<()> {
        let key = format!("key_bundle:{}", user_id);
        let _: i64 = self.client.del(&key).await?;
        tracing::debug!(user_id = %user_id, "Invalidated key bundle cache");
        Ok(())
    }

    /// Cache federation key bundle response (includes user_id, username, bundle)
    /// Used for federation key exchange endpoint
    pub(crate) async fn cache_federation_key_bundle(
        &mut self,
        user_id: &str,
        response_json: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("federation_key_bundle:{}", user_id);
        let _: () = self
            .client
            .set_ex(&key, response_json, ttl_seconds as u64)
            .await?;
        tracing::debug!(
            user_id = %user_id,
            ttl_seconds = ttl_seconds,
            "Cached federation key bundle"
        );
        Ok(())
    }

    /// Get cached federation key bundle response
    pub(crate) async fn get_cached_federation_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<String>> {
        let key = format!("federation_key_bundle:{}", user_id);
        let cached: Option<String> = self.client.get(&key).await?;
        Ok(cached)
    }
}
