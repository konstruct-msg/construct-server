//! Shared service dependencies and their builder.

use construct_auth::AuthManager;
use construct_config::Config;
use construct_db::DbPool;
use construct_federation::ServerSigner;

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
}

impl AppContext {
    /// Create a new AppContext using builder pattern (Phase 2.7)
    pub fn builder() -> AppContextBuilder {
        AppContextBuilder::new()
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
}

impl AppContextBuilder {
    pub fn new() -> Self {
        Self {
            db_pool: None,
            queue: None,
            auth_manager: None,
            config: None,
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

    /// Build AppContext from builder
    pub fn build(self) -> Result<AppContext, String> {
        let config = self
            .config
            .ok_or_else(|| "Config is required".to_string())?;

        Ok(AppContext {
            db_pool: self
                .db_pool
                .ok_or_else(|| "db_pool is required".to_string())?,
            queue: self.queue.ok_or_else(|| "queue is required".to_string())?,
            auth_manager: self
                .auth_manager
                .ok_or_else(|| "auth_manager is required".to_string())?,
            config,
        })
    }
}

impl Default for AppContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod contract_tests;
