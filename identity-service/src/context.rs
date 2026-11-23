use construct_config::Config;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::{
    auth::AuthManager, context::AppContext, db::DbPool, federation::signing::ServerSigner,
    queue::MessageQueue,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct IdentityServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
    pub server_signer: Option<Arc<ServerSigner>>,
    pub token_enc_pub: Option<[u8; 32]>,
    /// Privacy Pass issuer commitment `K = k·G` (compressed Ristretto) — published in well-known as
    /// `token_issuer_public` so clients can pin it and verify the DLEQ proof on each issuance
    /// (Phase C verifiable VOPRF). `None` when `TOKEN_ISSUER_KEY` is unset.
    pub token_issuer_pub: Option<[u8; 32]>,
    /// Version of the committed issuer key, published as `token_issuer_key_version` and echoed in
    /// `IssueTokensResponse.issuer_key_version` so key rotation is not a flag-day.
    pub token_issuer_key_version: u32,
    pub notification_client: Option<NotificationClient>,
}

impl IdentityServiceContext {
    /// Convert to shared AppContext for legacy handlers.
    ///
    /// Runs on every auth RPC, so it only clones handles: no client, cipher or cache
    /// is built here.
    pub fn to_app_context(&self) -> AppContext {
        AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .build()
            .expect("Failed to build AppContext in identity service")
    }
}
