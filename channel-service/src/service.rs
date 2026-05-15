use std::sync::Arc;

use construct_server_shared::clients::mls::MlsClient;

#[derive(Clone)]
pub(crate) struct ChannelServiceImpl {
    pub(crate) db: Arc<sqlx::PgPool>,
    pub(crate) mls_client: Option<MlsClient>,
}
