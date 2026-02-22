// ============================================================================
// AppContext Traits - Phase 2.7
// ============================================================================
//
// Trait-based interfaces for testing and dependency injection.
// Allows easy mocking of AppContext components in tests.
//
// Usage in tests:
// ```rust
// use construct_server::context::traits::*;
//
// // Create a mock that implements AppContextProvider
// struct MockAppContext { ... }
// impl DatabaseProvider for MockAppContext { ... }
// impl MessageProvider for MockAppContext { ... }
// // ... etc
// impl AppContextProvider for MockAppContext {}
// ```
//
// ============================================================================

#![allow(dead_code)] // Traits are for future use in tests and mocking

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::db::DbPool;
use crate::delivery_ack::{DeliveryAckManager, PostgresDeliveryStorage};
use crate::federation::{PublicKeyCache, ServerSigner};
use construct_config::Config;

use crate::kafka::MessageProducer;
// MessageGatewayClient removed - was only used for WebSocket
use crate::queue::MessageQueue;

/// Trait for database operations (for testing and dependency injection)
#[allow(dead_code)]
pub trait DatabaseProvider: Send + Sync {
    fn pool(&self) -> &Arc<DbPool>;
}

/// Trait for message operations (for testing and dependency injection)
#[allow(dead_code)]
pub trait MessageProvider: Send + Sync {
    fn queue(&self) -> &Arc<Mutex<MessageQueue>>;
    fn kafka_producer(&self) -> Option<&Arc<MessageProducer>>;
    // gateway_client removed
}

/// Trait for authentication operations (for testing and dependency injection)
#[allow(dead_code)]
pub trait AuthProvider: Send + Sync {
    fn manager(&self) -> &Arc<AuthManager>;
}

/// Trait for notification operations (for testing and dependency injection)
#[allow(dead_code)]
pub trait NotificationProvider: Send + Sync {
    fn apns_client(&self) -> &Arc<ApnsClient>;
    fn token_encryption(&self) -> &Arc<DeviceTokenEncryption>;
}

/// Trait for federation operations (for testing and dependency injection)
#[allow(dead_code)]
pub trait FederationProvider: Send + Sync {
    fn server_signer(&self) -> Option<&Arc<ServerSigner>>;
    fn public_key_cache(&self) -> &Arc<PublicKeyCache>;
}

/// Trait for delivery operations (for testing and dependency injection)
#[allow(dead_code)]
pub trait DeliveryProvider: Send + Sync {
    fn delivery_ack_manager(&self) -> Option<&Arc<DeliveryAckManager<PostgresDeliveryStorage>>>;
}

/// Trait for configuration (for testing and dependency injection)
#[allow(dead_code)]
pub trait ConfigProvider: Send + Sync {
    fn config(&self) -> &Arc<Config>;
    fn server_instance_id(&self) -> &str;
}

/// Combined trait for all AppContext operations (for testing and dependency injection)
///
/// This trait allows mocking the entire AppContext in tests.
/// Implement this trait for test doubles/mocks.
#[allow(dead_code)]
pub trait AppContextProvider:
    DatabaseProvider
    + MessageProvider
    + NotificationProvider
    + FederationProvider
    + DeliveryProvider
    + ConfigProvider
    + Send
    + Sync
{
}

// Implement traits for AppContext
impl DatabaseProvider for crate::context::AppContext {
    fn pool(&self) -> &Arc<DbPool> {
        &self.db_pool
    }
}

impl MessageProvider for crate::context::AppContext {
    fn queue(&self) -> &Arc<Mutex<MessageQueue>> {
        &self.queue
    }

    fn kafka_producer(&self) -> Option<&Arc<MessageProducer>> {
        self.kafka_producer.as_ref()
    }

    // gateway_client removed
}

impl NotificationProvider for crate::context::AppContext {
    fn apns_client(&self) -> &Arc<ApnsClient> {
        &self.apns_client
    }

    fn token_encryption(&self) -> &Arc<DeviceTokenEncryption> {
        &self.token_encryption
    }
}

impl FederationProvider for crate::context::AppContext {
    fn server_signer(&self) -> Option<&Arc<ServerSigner>> {
        self.server_signer.as_ref()
    }

    fn public_key_cache(&self) -> &Arc<PublicKeyCache> {
        &self.public_key_cache
    }
}

impl DeliveryProvider for crate::context::AppContext {
    fn delivery_ack_manager(&self) -> Option<&Arc<DeliveryAckManager<PostgresDeliveryStorage>>> {
        self.delivery_ack_manager.as_ref()
    }
}

impl ConfigProvider for crate::context::AppContext {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn server_instance_id(&self) -> &str {
        &self.server_instance_id
    }
}

// AppContext implements AppContextProvider
impl AppContextProvider for crate::context::AppContext {}
