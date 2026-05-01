use std::sync::Arc;

use sqlx::PgPool;

#[derive(Clone)]
pub(crate) struct ChannelServiceImpl {
    #[allow(dead_code)]
    pub(crate) db: Arc<PgPool>,
}
