//! Shared service dependencies and their builder.

use construct_apns::{ApnsClient, DeviceTokenEncryption};
use construct_auth::AuthManager;
use construct_config::Config;
use construct_db::DbPool;
use construct_federation::{PublicKeyCache, ServerSigner};

use construct_queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Application context containing shared dependencies
#[derive(Clone)]
pub struct AppContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
    /// APNs client for push notifications (production tokens)
    /// Optional: only required for services that send push notifications directly.
    /// messaging-service delegates push to notification-service via gRPC and leaves this None.
    pub apns_client: Option<Arc<ApnsClient>>,
    /// APNs sandbox client for development/TestFlight tokens
    pub apns_sandbox_client: Option<Arc<ApnsClient>>,
    /// Device token encryption for privacy
    /// Optional: only required for services that register/decrypt device tokens.
    pub token_encryption: Option<Arc<DeviceTokenEncryption>>,
    /// Unique identifier for this server instance (`user:{id}:server_instance_id`)
    pub server_instance_id: String,
    /// Server signer for S2S federation authentication
    /// When None: federation signing is disabled (messages sent unsigned)
    /// When Some: sign outgoing S2S messages with Ed25519
    pub server_signer: Option<Arc<ServerSigner>>,
    /// Cache for remote server public keys (for signature verification)
    pub public_key_cache: Arc<PublicKeyCache>,
}

impl AppContext {
    /// Create a new AppContext using builder pattern (Phase 2.7)
    pub fn builder() -> AppContextBuilder {
        AppContextBuilder::new()
    }

    /// Initialize the builder's server signer from config.
    fn init_server_signer(config: &Config) -> Option<Arc<ServerSigner>> {
        Self::init_server_signer_pub(config)
    }

    /// Public helper: initialize server signer from config.
    /// Available to services that build their own context (e.g. messaging-service).
    pub fn init_server_signer_pub(config: &Config) -> Option<Arc<ServerSigner>> {
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
}

/// Builder for AppContext (simplifies creation)
pub struct AppContextBuilder {
    db_pool: Option<Arc<DbPool>>,
    queue: Option<Arc<Mutex<MessageQueue>>>,
    auth_manager: Option<Arc<AuthManager>>,
    config: Option<Arc<Config>>,
    apns_client: Option<Arc<ApnsClient>>,
    apns_sandbox_client: Option<Arc<ApnsClient>>,
    token_encryption: Option<Arc<DeviceTokenEncryption>>,
    server_instance_id: Option<String>,
    server_signer_override: Option<Arc<ServerSigner>>,
}

impl AppContextBuilder {
    pub fn new() -> Self {
        Self {
            db_pool: None,
            queue: None,
            auth_manager: None,
            config: None,
            apns_client: None,
            apns_sandbox_client: None,
            token_encryption: None,
            server_instance_id: None,
            server_signer_override: None,
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

    pub fn with_server_signer(mut self, signer: Arc<ServerSigner>) -> Self {
        self.server_signer_override = Some(signer);
        self
    }

    /// Build AppContext from builder
    ///
    /// Initializes server_signer and public_key_cache from config if available.
    pub fn build(self) -> Result<AppContext, String> {
        let config = self
            .config
            .ok_or_else(|| "Config is required".to_string())?;

        // Use override signer if provided, otherwise init from config
        let server_signer = self
            .server_signer_override
            .or_else(|| AppContext::init_server_signer(&config));

        Ok(AppContext {
            db_pool: self
                .db_pool
                .ok_or_else(|| "db_pool is required".to_string())?,
            queue: self.queue.ok_or_else(|| "queue is required".to_string())?,
            auth_manager: self
                .auth_manager
                .ok_or_else(|| "auth_manager is required".to_string())?,
            config,
            apns_client: self.apns_client,
            apns_sandbox_client: self.apns_sandbox_client,
            token_encryption: self.token_encryption,
            server_instance_id: self
                .server_instance_id
                .ok_or_else(|| "server_instance_id is required".to_string())?,
            server_signer,
            public_key_cache: Arc::new(PublicKeyCache::new()),
        })
    }
}

impl Default for AppContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}
