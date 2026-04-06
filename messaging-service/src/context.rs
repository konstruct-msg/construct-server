// ============================================================================
// Messaging Service - Phase 2.6.4 + APNs Integration
// ============================================================================
//
// Minimal context and utilities for Messaging Service microservice.
//
// Phase 2.9: Added APNs support for push notifications
// - APNs client for sending silent push notifications
// - Integrated directly into messaging service for low latency
//
// ============================================================================

use construct_apns::{ApnsClient, DeviceTokenEncryption};
use construct_auth::AuthManager;
use construct_broker::MessageProducer;
use construct_config::Config;
use construct_context::AppContext;
use construct_db::DbPool;
use construct_federation::ServerSigner;
use construct_key_management::KeyManagementSystem;
use construct_queue::MessageQueue;
use construct_server_shared::clients::notification::NotificationClient;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Messaging Service context
#[derive(Clone)]
#[allow(dead_code)]
pub struct MessagingServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub kafka_producer: Arc<MessageProducer>,
    /// APNs production client (kept for to_app_context adapter compatibility)
    pub apns_client: Arc<ApnsClient>,
    /// APNs sandbox client (kept for to_app_context adapter compatibility)
    pub apns_sandbox_client: Arc<ApnsClient>,
    /// Device token encryption (kept for to_app_context adapter compatibility)
    pub token_encryption: Arc<DeviceTokenEncryption>,
    /// gRPC client for notification-service — used for silent push instead of calling APNs directly
    pub notification_client: Option<NotificationClient>,
    pub config: Arc<Config>,
    pub key_management: Option<Arc<KeyManagementSystem>>,
    /// Server signer for S2S federation authentication (sealed sender forwarding)
    pub server_signer: Option<Arc<ServerSigner>>,
}

impl MessagingServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> AppContext {
        // Create AppContext using builder pattern (Phase 2.8)
        let builder = AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_kafka_producer(self.kafka_producer.clone())
            .with_apns_client(self.apns_client.clone())
            .with_apns_sandbox_client(self.apns_sandbox_client.clone())
            .with_token_encryption(self.token_encryption.clone())
            .with_server_instance_id(uuid::Uuid::new_v4().to_string());

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
    /// Briefly locks the queue to clone the ConnectionManager, then releases the lock.
    /// The returned handle is independent — callers do not hold the queue lock during use.
    pub async fn redis_conn(&self) -> anyhow::Result<redis::aio::ConnectionManager> {
        let queue = self.queue.lock().await;
        Ok(queue.clone_redis_connection())
    }
}
