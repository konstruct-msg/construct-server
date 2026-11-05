// ============================================================================
// Notification Service - Phase 2.6.5
// ============================================================================
//
// Minimal context and utilities for Notification Service microservice.
//
// ============================================================================

use construct_apns::{ApnsClient, DeviceTokenEncryption};
use construct_auth::AuthManager;
use construct_config::Config;
use construct_db::DbPool;
use construct_queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Notification Service context (minimal dependencies)
#[derive(Clone)]
pub struct NotificationServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    /// APNS client for production tokens (api.push.apple.com)
    pub apns_client: Arc<ApnsClient>,
    /// APNS client for sandbox tokens (api.sandbox.push.apple.com)
    pub apns_sandbox_client: Arc<ApnsClient>,
    pub token_encryption: Arc<DeviceTokenEncryption>,
    pub config: Arc<Config>,
}
