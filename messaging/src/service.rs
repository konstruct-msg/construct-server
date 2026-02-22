// ============================================================================
// Messaging Service Context
// ============================================================================
//
// Minimal context and utilities for Messaging Service microservice.
// Separated from shared crate to reduce binary footprint.
//
// ============================================================================

use construct_server_shared::auth::AuthManager;
use construct_config::Config;
use construct_server_shared::db::DbPool;
use construct_server_shared::key_management::KeyManagementSystem;
use construct_server_shared::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Messaging Service context (minimal dependencies)
#[derive(Clone)]
pub struct MessagingServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
    // Kafka producer is messaging-specific, will be added when moving kafka module
    // pub kafka_producer: Arc<MessageProducer>,
}

impl MessagingServiceContext {
    pub fn new(
        db_pool: Arc<DbPool>,
        queue: Arc<Mutex<MessageQueue>>,
        auth_manager: Arc<AuthManager>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            db_pool,
            queue,
            auth_manager,
            config,
        }
    }

    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> construct_server_shared::context::AppContext {
        use construct_server_shared::apns::{ApnsClient, DeviceTokenEncryption};

        // WebSocket clients removed - no longer needed
        // Messaging handlers don't use Kafka directly in routes (only through delivery worker)
        let kafka_producer: Option<
            std::sync::Arc<construct_server_shared::kafka::MessageProducer>,
        > = None;

        // Create minimal APNs client (not used by messaging handlers)
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "APNs client creation failed in messaging service - messaging handlers don't use APNs, continuing");
                panic!("APNs client is required but not available - this should not happen in messaging service")
            });

        // Create minimal token encryption (not used by messaging handlers)
        let token_encryption = construct_server_shared::apns::DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Token encryption creation failed in messaging service - messaging handlers don't use it, continuing");
                panic!("Token encryption is required but not available - this should not happen in messaging service")
            });

        // Create AppContext using builder pattern (Phase 2.8)
        construct_server_shared::context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_apns_client(apns_client)
            .with_token_encryption(token_encryption)
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext")
    }
}
