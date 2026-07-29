// ============================================================================
// Auth Service - Phase 2.6.2
// ============================================================================
//
// Minimal context and utilities for Auth Service microservice.
//
// ============================================================================

use construct_auth::AuthManager;
use construct_config::Config;
use construct_db::DbPool;
use construct_federation::signing::ServerSigner;

use construct_queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Auth Service context (minimal dependencies)
#[derive(Clone)]
pub struct AuthServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
    pub server_signer: Option<Arc<ServerSigner>>,
    /// X25519 public key (32 bytes) used to encrypt Privacy Pass token_bytes in SealedInner.
    /// Clients encrypt tokens to this key so relay operators cannot read them in transit.
    /// Derived from signing_key_seed via HKDF(info="construct-token-enc-v1").
    /// Published at /.well-known/construct-server as `token_encryption_key` (base64).
    pub token_enc_pub: Option<[u8; 32]>,
}

impl AuthServiceContext {
    /// Convert to AppContext for use with existing handlers.
    ///
    /// APNs / device-token encryption are **optional** on AppContext and unused by
    /// auth handlers — leave them `None` rather than panicking if credentials are
    /// missing or malformed (P2-3).
    pub fn to_app_context(&self) -> construct_context::AppContext {
        construct_context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext for auth service")
    }
}

impl construct_db::HasDbPool for AuthServiceContext {
    fn db_pool(&self) -> &std::sync::Arc<construct_db::DbPool> {
        &self.db_pool
    }
}
