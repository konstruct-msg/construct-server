// ============================================================================
// User Service - Phase 2.6.3
// ============================================================================
//
// Minimal context and utilities for User Service microservice.
//
// ============================================================================

pub mod core;
pub mod handlers;

use crate::auth::AuthManager;
use crate::db::DbPool;
use construct_config::Config;

use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// User Service context (minimal dependencies)
#[derive(Clone)]
pub struct UserServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
}

impl UserServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        use crate::apns::{ApnsClient, DeviceTokenEncryption};

        // WebSocket clients removed - no longer needed

        // User handlers don't use Kafka, so we can skip creating the producer
        let kafka_producer = match crate::kafka::MessageProducer::new(&self.config.kafka) {
            Ok(producer) => Some(Arc::new(producer)),
            Err(e) => {
                tracing::warn!(error = %e, "Kafka producer creation failed in user service - user handlers don't use Kafka, continuing without it");
                None
            }
        };

        // Create minimal APNs client (not used by user handlers)
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "APNs client creation failed in user service - user handlers don't use APNs, continuing");
                panic!("APNs client is required but not available - this should not happen in user service")
            });

        // Create minimal token encryption (not used by user handlers)
        let token_encryption = Arc::new(
            DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Token encryption creation failed in user service");
                    panic!("Token encryption is required but not available - this should not happen in user service")
                })
        );

        // Create AppContext using builder pattern (Phase 2.8)
        let mut builder = crate::context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone());

        // Only set kafka_producer if available (user service doesn't require it)
        if let Some(kafka_producer) = kafka_producer {
            builder = builder.with_kafka_producer(kafka_producer);
        }

        builder
            .with_apns_client(apns_client)
            .with_token_encryption(token_encryption)
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext for user service")
    }
}
