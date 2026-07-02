// ============================================================================
// Messaging Service - Phase 2.6.4
// ============================================================================
//
// Minimal context and utilities for Messaging Service microservice.
//
// ============================================================================

use construct_auth::AuthManager;
use construct_config::Config;
use construct_context::AppContext;
use construct_db::DbPool;
use construct_federation::ServerSigner;
use construct_queue::MessageQueue;
use construct_server_shared::notification_service::NotificationServiceContext;
use construct_server_shared::sentinel_service::SentinelCore;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Messaging Service context
#[derive(Clone)]
#[allow(dead_code)]
pub struct MessagingServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    /// Embedded notification context for direct push (APNs) — replaces former gRPC round-trip to notification-service
    pub notification_context: Option<Arc<NotificationServiceContext>>,
    /// Embedded Sentinel core — rate limiting and spam protection, in-process
    /// (former gRPC round-trip to sentinel-service has been replaced by a
    /// direct call to `SentinelCore`).
    pub sentinel: Option<std::sync::Arc<SentinelCore>>,
    pub config: Arc<Config>,
    /// Server signer for S2S federation authentication (sealed sender forwarding)
    pub server_signer: Option<Arc<ServerSigner>>,
    /// Stable ID for this process instance — stored in Redis at stream open.
    pub server_instance_id: String,
    /// Standalone Redis ConnectionManager for rate-limiting and caching.
    /// Cloned lock-free without acquiring the queue Mutex.
    pub redis_conn: redis::aio::ConnectionManager,
    /// Privacy Pass token issuer scalar `k` (`TOKEN_ISSUER_KEY`), shared with
    /// identity-service's `IssueTokens`. `None` disables redemption regardless
    /// of `config.messaging.stealth_token_policy`.
    pub token_issuer_key: Option<[u8; 32]>,
    /// X25519 static secret for opening `SealedInner.token_bytes`, derived from
    /// `federation.signing_key_seed` — same derivation identity-service uses to
    /// publish the public half at `/.well-known/construct-server`.
    pub token_enc_static_secret: Option<x25519_dalek::StaticSecret>,
}

impl MessagingServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> AppContext {
        let builder = AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_server_instance_id(self.server_instance_id.clone());

        let builder = if let Some(signer) = &self.server_signer {
            builder.with_server_signer(signer.clone())
        } else {
            builder
        };

        builder
            .build()
            .expect("Failed to build AppContext for messaging service")
    }
}

impl construct_db::HasDbPool for MessagingServiceContext {
    fn db_pool(&self) -> &std::sync::Arc<construct_db::DbPool> {
        &self.db_pool
    }
}

impl MessagingServiceContext {
    /// Get a Redis ConnectionManager for rate-limiting and caching.
    ///
    /// Returns a clone of the standalone ConnectionManager — O(1), no lock acquired.
    pub async fn redis_conn(&self) -> anyhow::Result<redis::aio::ConnectionManager> {
        Ok(self.redis_conn.clone())
    }
}
