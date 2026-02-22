// ============================================================================
// AppContext - Phase 2.7 Refactoring
// ============================================================================
//
// Phase 2.7 improvements:
// - Logical grouping methods (db(), messages(), auth(), etc.)
// - Builder pattern (AppContextBuilder)
// - Trait-based interfaces for testing (see context/traits.rs)
//
// ============================================================================

// Trait-based interfaces for testing and dependency injection (Phase 2.7)
pub mod traits;

use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::db::DbPool;
use crate::delivery_ack::{DeliveryAckManager, PostgresDeliveryStorage};
use crate::federation::{PublicKeyCache, ServerSigner};
use crate::pending_messages::PendingMessageStorage;
use construct_config::Config;

use crate::kafka::MessageProducer;
use crate::key_management::KeyManagementSystem;
// MessageGatewayClient removed - was only used for WebSocket message processing
use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Application context containing shared dependencies
///
/// **Phase 2.7 Refactoring:** This structure will be refactored into logical groups:
/// - DatabaseContext (db_pool)
/// - MessageContext (queue, kafka_producer)
/// - AuthContext (auth_manager, clients)
/// - NotificationContext (apns_client, token_encryption)
/// - FederationContext (server_signer, public_key_cache)
/// - DeliveryContext (delivery_ack_manager)
/// - ConfigContext (config, server_instance_id)
///
/// For now, we keep the flat structure for backward compatibility.
#[derive(Clone)]
pub struct AppContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
    /// Kafka producer for reliable message delivery (Phase 1+)
    /// Optional: some services (like auth) don't need Kafka
    pub kafka_producer: Option<Arc<MessageProducer>>,
    /// APNs client for push notifications
    pub apns_client: Arc<ApnsClient>,
    /// Device token encryption for privacy
    pub token_encryption: Arc<DeviceTokenEncryption>,
    /// Unique identifier for this server instance (for delivery worker coordination)
    pub server_instance_id: String,
    /// Message Gateway client for delegating message processing (Phase 2+)
    /// When None: process messages locally (legacy mode)
    /// When Some: forward to Message Gateway service via gRPC
    // gateway_client removed - was only used for WebSocket message processing via message-gateway
    // REST API routes send directly to Kafka
    /// Delivery ACK manager for privacy-preserving message delivery confirmations
    /// When None: delivery ACK system is disabled
    /// When Some: track and route delivery acknowledgments
    pub delivery_ack_manager: Option<Arc<DeliveryAckManager<PostgresDeliveryStorage>>>,
    /// Server signer for S2S federation authentication
    /// When None: federation signing is disabled (messages sent unsigned)
    /// When Some: sign outgoing S2S messages with Ed25519
    pub server_signer: Option<Arc<ServerSigner>>,
    /// Cache for remote server public keys (for signature verification)
    pub public_key_cache: Arc<PublicKeyCache>,
    /// Key management system for automatic key rotation (optional)
    /// When None: key management is disabled (uses static keys from config)
    /// When Some: automatic rotation, Vault integration, hot reload
    pub key_management: Option<Arc<KeyManagementSystem>>,
    /// Pending message storage for 2-phase commit protocol
    /// When None: 2-phase commit is disabled (legacy mode)
    /// When Some: idempotent message delivery with network failure recovery
    pub pending_message_storage: Option<Arc<PendingMessageStorage>>,
}

impl AppContext {
    /// Creates a new application context
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db_pool: Arc<DbPool>,
        queue: Arc<Mutex<MessageQueue>>,
        auth_manager: Arc<AuthManager>,
        config: Arc<Config>,
        kafka_producer: Option<Arc<MessageProducer>>,
        apns_client: Arc<ApnsClient>,
        token_encryption: Arc<DeviceTokenEncryption>,
        server_instance_id: String,
    ) -> Self {
        // Initialize server signer if signing key is configured
        let server_signer = Self::init_server_signer(&config);

        Self {
            db_pool,
            queue,
            auth_manager,
            config,
            kafka_producer,
            apns_client,
            token_encryption,
            server_instance_id,
            // gateway_client removed
            delivery_ack_manager: None, // Disabled by default
            server_signer,
            public_key_cache: Arc::new(PublicKeyCache::new()),
            key_management: None,          // Disabled by default
            pending_message_storage: None, // Disabled by default
        }
    }

    // new_with_gateway removed - message gateway was only used for WebSocket

    /// Set delivery ACK manager (builder pattern)
    pub fn with_delivery_ack_manager(
        mut self,
        manager: Arc<DeliveryAckManager<PostgresDeliveryStorage>>,
    ) -> Self {
        self.delivery_ack_manager = Some(manager);
        self
    }

    /// Set key management system (builder pattern)
    pub fn with_key_management(mut self, kms: Arc<KeyManagementSystem>) -> Self {
        self.key_management = Some(kms);
        self
    }

    /// Set pending message storage (builder pattern)
    pub fn with_pending_message_storage(mut self, storage: Arc<PendingMessageStorage>) -> Self {
        self.pending_message_storage = Some(storage);
        self
    }

    /// Create a new AppContext using builder pattern (Phase 2.7)
    pub fn builder() -> AppContextBuilder {
        AppContextBuilder::new()
    }

    /// Initialize server signer from config (Phase 2.8: Extract duplicated logic)
    ///
    /// This function extracts the duplicated server signer initialization logic
    /// that was previously in AppContext::new(), AppContext::new_with_gateway(),
    /// and AppContextBuilder::build().
    fn init_server_signer(config: &Config) -> Option<Arc<ServerSigner>> {
        config
            .federation
            .signing_key_seed
            .as_ref()
            .and_then(|seed| {
                ServerSigner::from_seed_base64(seed, config.federation.instance_domain.clone())
                    .map(Arc::new)
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to initialize server signer");
                        e
                    })
                    .ok()
            })
    }

    // ============================================================================
    // Phase 2.7: Logical grouping methods (for better organization)
    // ============================================================================

    /// Get database context (Phase 2.7)
    pub fn db(&self) -> DatabaseContextRef<'_> {
        DatabaseContextRef {
            pool: &self.db_pool,
        }
    }

    /// Get message context (Phase 2.7)
    pub fn messages(&self) -> MessageContextRef<'_> {
        MessageContextRef {
            queue: &self.queue,
            kafka_producer: self.kafka_producer.as_ref(),
            // gateway_client removed
        }
    }

    /// Get auth context (Phase 2.7)
    pub fn auth(&self) -> AuthContextRef<'_> {
        AuthContextRef {
            manager: &self.auth_manager,
        }
    }

    /// Get notification context (Phase 2.7)
    pub fn notifications(&self) -> NotificationContextRef<'_> {
        NotificationContextRef {
            apns_client: &self.apns_client,
            token_encryption: &self.token_encryption,
        }
    }

    /// Get federation context (Phase 2.7)
    pub fn federation(&self) -> FederationContextRef<'_> {
        FederationContextRef {
            server_signer: self.server_signer.as_ref(),
            public_key_cache: &self.public_key_cache,
        }
    }

    /// Get delivery context (Phase 2.7)
    pub fn delivery(&self) -> DeliveryContextRef<'_> {
        DeliveryContextRef {
            manager: self.delivery_ack_manager.as_ref(),
        }
    }

    /// Get config context (Phase 2.7)
    pub fn config_ctx(&self) -> ConfigContextRef<'_> {
        ConfigContextRef {
            config: &self.config,
            server_instance_id: &self.server_instance_id,
        }
    }
}

// ============================================================================
// Phase 2.7: Logical grouping reference types
// ============================================================================

/// Database context reference (Phase 2.7)
pub struct DatabaseContextRef<'a> {
    pub pool: &'a Arc<DbPool>,
}

/// Message context reference (Phase 2.7)
pub struct MessageContextRef<'a> {
    pub queue: &'a Arc<Mutex<MessageQueue>>,
    pub kafka_producer: Option<&'a Arc<MessageProducer>>,
    // gateway_client removed
}

/// Auth context reference (Phase 2.7)
pub struct AuthContextRef<'a> {
    pub manager: &'a Arc<AuthManager>,
}

/// Notification context reference (Phase 2.7)
pub struct NotificationContextRef<'a> {
    pub apns_client: &'a Arc<ApnsClient>,
    pub token_encryption: &'a Arc<DeviceTokenEncryption>,
}

/// Federation context reference (Phase 2.7)
pub struct FederationContextRef<'a> {
    pub server_signer: Option<&'a Arc<ServerSigner>>,
    pub public_key_cache: &'a Arc<PublicKeyCache>,
}

/// Delivery context reference (Phase 2.7)
pub struct DeliveryContextRef<'a> {
    pub manager: Option<&'a Arc<DeliveryAckManager<PostgresDeliveryStorage>>>,
}

/// Config context reference (Phase 2.7)
pub struct ConfigContextRef<'a> {
    pub config: &'a Arc<Config>,
    pub server_instance_id: &'a str,
}

// ============================================================================
// Phase 2.7: Builder pattern for AppContext
// ============================================================================

/// Builder for AppContext (simplifies creation)
pub struct AppContextBuilder {
    db_pool: Option<Arc<DbPool>>,
    queue: Option<Arc<Mutex<MessageQueue>>>,
    auth_manager: Option<Arc<AuthManager>>,
    config: Option<Arc<Config>>,
    kafka_producer: Option<Arc<MessageProducer>>,
    apns_client: Option<Arc<ApnsClient>>,
    token_encryption: Option<Arc<DeviceTokenEncryption>>,
    server_instance_id: Option<String>,
    // gateway_client removed
    delivery_ack_manager: Option<Arc<DeliveryAckManager<PostgresDeliveryStorage>>>,
    key_management: Option<Arc<KeyManagementSystem>>,
    pending_message_storage: Option<Arc<PendingMessageStorage>>,
}

impl AppContextBuilder {
    pub fn new() -> Self {
        Self {
            db_pool: None,
            queue: None,
            auth_manager: None,
            config: None,
            kafka_producer: None,
            apns_client: None,
            token_encryption: None,
            server_instance_id: None,
            // gateway_client removed
            delivery_ack_manager: None,
            key_management: None,
            pending_message_storage: None,
        }
    }

    pub fn with_db_pool(mut self, db_pool: Arc<DbPool>) -> Self {
        self.db_pool = Some(db_pool);
        self
    }

    pub fn with_queue(mut self, queue: Arc<Mutex<MessageQueue>>) -> Self {
        self.queue = Some(queue);
        self
    }

    pub fn with_auth_manager(mut self, auth_manager: Arc<AuthManager>) -> Self {
        self.auth_manager = Some(auth_manager);
        self
    }

    pub fn with_config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_kafka_producer(mut self, kafka_producer: Arc<MessageProducer>) -> Self {
        self.kafka_producer = Some(kafka_producer);
        self
    }

    pub fn with_apns_client(mut self, apns_client: Arc<ApnsClient>) -> Self {
        self.apns_client = Some(apns_client);
        self
    }

    pub fn with_token_encryption(mut self, token_encryption: Arc<DeviceTokenEncryption>) -> Self {
        self.token_encryption = Some(token_encryption);
        self
    }

    pub fn with_server_instance_id(mut self, server_instance_id: String) -> Self {
        self.server_instance_id = Some(server_instance_id);
        self
    }

    // with_gateway_client removed - message gateway was only used for WebSocket

    pub fn with_delivery_ack_manager(
        mut self,
        manager: Arc<DeliveryAckManager<PostgresDeliveryStorage>>,
    ) -> Self {
        self.delivery_ack_manager = Some(manager);
        self
    }

    pub fn with_key_management(mut self, kms: Arc<KeyManagementSystem>) -> Self {
        self.key_management = Some(kms);
        self
    }

    pub fn with_pending_message_storage(mut self, storage: Arc<PendingMessageStorage>) -> Self {
        self.pending_message_storage = Some(storage);
        self
    }

    /// Build AppContext from builder
    ///
    /// Initializes server_signer and public_key_cache from config if available.
    pub fn build(self) -> Result<AppContext, String> {
        let config = self
            .config
            .ok_or_else(|| "Config is required".to_string())?;

        // Initialize server signer if signing key is configured
        let server_signer = AppContext::init_server_signer(&config);

        Ok(AppContext {
            db_pool: self
                .db_pool
                .ok_or_else(|| "db_pool is required".to_string())?,
            queue: self.queue.ok_or_else(|| "queue is required".to_string())?,
            auth_manager: self
                .auth_manager
                .ok_or_else(|| "auth_manager is required".to_string())?,
            config,
            kafka_producer: self.kafka_producer,
            apns_client: self
                .apns_client
                .ok_or_else(|| "apns_client is required".to_string())?,
            token_encryption: self
                .token_encryption
                .ok_or_else(|| "token_encryption is required".to_string())?,
            server_instance_id: self
                .server_instance_id
                .ok_or_else(|| "server_instance_id is required".to_string())?,
            // gateway_client removed
            delivery_ack_manager: self.delivery_ack_manager,
            server_signer,
            public_key_cache: Arc::new(PublicKeyCache::new()),
            key_management: self.key_management,
            pending_message_storage: self.pending_message_storage,
        })
    }
}

impl Default for AppContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}
