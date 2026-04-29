use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct MlsServiceImpl {
    pub(crate) db: Arc<sqlx::PgPool>,
}
