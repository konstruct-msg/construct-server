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

pub mod core;
pub mod handlers;

use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::db::DbPool;
use construct_config::Config;

use crate::kafka::MessageProducer;
use crate::key_management::KeyManagementSystem;
use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Messaging Service context
#[derive(Clone)]
pub struct MessagingServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub kafka_producer: Arc<MessageProducer>,
    /// APNs client for sending push notifications when messages arrive
    pub apns_client: Arc<ApnsClient>,
    /// Device token encryption for decrypting tokens before sending push
    pub token_encryption: Arc<DeviceTokenEncryption>,
    pub config: Arc<Config>,
    pub key_management: Option<Arc<KeyManagementSystem>>,
}

impl MessagingServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        // Create AppContext using builder pattern (Phase 2.8)
        crate::context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_kafka_producer(self.kafka_producer.clone())
            .with_apns_client(self.apns_client.clone())
            .with_token_encryption(self.token_encryption.clone())
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext for messaging service")
    }
}
