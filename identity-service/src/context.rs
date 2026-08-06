use construct_config::Config;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::{
    apns::{ApnsClient, DeviceTokenEncryption},
    auth::AuthManager,
    context::AppContext,
    db::DbPool,
    federation::signing::ServerSigner,
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
    /// APNs + token encryption are optional on AppContext. Identity paths that need
    /// them (device-token registration) construct them at the call site; the adapter
    /// must not panic when APNs keys are absent (P2-3).
    pub fn to_app_context(&self) -> AppContext {
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .map_err(|e| {
                tracing::debug!(error = %e, "APNs client not configured for identity AppContext adapter");
                e
            })
            .ok();

        let token_encryption =
            DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
                .map(Arc::new)
                .map_err(|e| {
                    tracing::debug!(
                        error = %e,
                        "Token encryption not configured for identity AppContext adapter"
                    );
                    e
                })
                .ok();

        let mut builder = AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_server_instance_id(uuid::Uuid::new_v4().to_string());

        if let Some(signer) = &self.server_signer {
            builder = builder.with_server_signer(signer.clone());
        }
        if let Some(client) = apns_client {
            builder = builder.with_apns_client(client);
        }
        if let Some(enc) = token_encryption {
            builder = builder.with_token_encryption(enc);
        }

        builder
            .build()
            .expect("Failed to build AppContext in identity service")
    }
}

impl construct_server_shared::db::HasDbPool for IdentityServiceContext {
    fn db_pool(&self) -> &Arc<DbPool> {
        &self.db_pool
    }
}
