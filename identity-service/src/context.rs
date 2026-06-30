use construct_server_shared::{
    apns::{ApnsClient, DeviceTokenEncryption},
    auth::AuthManager,
    context::AppContext,
    db::DbPool,
    federation::signing::ServerSigner,
    queue::MessageQueue,
};
use construct_config::Config;
use construct_server_shared::clients::notification::NotificationClient;
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
    pub notification_client: Option<NotificationClient>,
}

impl IdentityServiceContext {
    pub fn to_app_context(&self) -> AppContext {
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "APNs client unavailable in identity service");
                panic!("APNs client required but not available")
            });

        let token_encryption =
            DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
                .map(Arc::new)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Token encryption unavailable in identity service");
                    panic!("Token encryption required but not available")
                });

        AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_config(self.config.clone())
            .with_apns_client(apns_client)
            .with_token_encryption(token_encryption)
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext in identity service")
    }
}

impl construct_server_shared::db::HasDbPool for IdentityServiceContext {
    fn db_pool(&self) -> &Arc<DbPool> {
        &self.db_pool
    }
}
