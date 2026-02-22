// ============================================================================
// Notification Service - Phase 2.6.5
// ============================================================================
//
// Minimal context and utilities for Notification Service microservice.
//
// ============================================================================

pub mod handlers;

use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::db::DbPool;
use construct_config::Config;

use crate::key_management::KeyManagementSystem;
use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Notification Service context (minimal dependencies)
#[derive(Clone)]
pub struct NotificationServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub apns_client: Arc<ApnsClient>,
    pub token_encryption: Arc<DeviceTokenEncryption>,
    pub config: Arc<Config>,
    pub key_management: Option<Arc<KeyManagementSystem>>,
}

impl NotificationServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        use crate::kafka::MessageProducer;

        // WebSocket clients removed - no longer needed

        // Notification handlers don't use Kafka, so we can skip creating the producer
        let kafka_producer = match MessageProducer::new(&self.config.kafka) {
            Ok(producer) => Some(Arc::new(producer)),
            Err(e) => {
                tracing::warn!(error = %e, "Kafka producer creation failed in notification service - notification handlers don't use Kafka, continuing without it");
                None
            }
        };

        // Create AppContext using builder pattern (Phase 2.8)
        let mut builder = crate::context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone());

        // Only set kafka_producer if available (notification service doesn't require it)
        if let Some(kafka_producer) = kafka_producer {
            builder = builder.with_kafka_producer(kafka_producer);
        }

        builder
            .with_apns_client(self.apns_client.clone())
            .with_token_encryption(self.token_encryption.clone())
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext for notification service")
    }
}
