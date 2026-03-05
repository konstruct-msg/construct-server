// Auth service business logic is in crates/construct-auth-service.
// This module re-exports it and adds proto adapters that need access to the
// shared proto types (not available in the standalone crate).

pub use construct_auth_service::context::AuthServiceContext;
pub use construct_auth_service::devices;

pub mod core {
    pub use construct_auth_service::core::*;

    use crate::shared::proto::services::v1 as proto_services;
    use construct_context::AppContext;
    use construct_error::AppError;
    use std::sync::Arc;

    /// Proto adapter: wraps refresh_tokens with gRPC request/response types.
    pub async fn refresh_tokens_proto(
        app_context: Arc<AppContext>,
        request: proto_services::RefreshTokenRequest,
    ) -> Result<proto_services::RefreshTokenResponse, AppError> {
        let result = refresh_tokens(app_context, &request.refresh_token).await?;
        Ok(proto_services::RefreshTokenResponse {
            access_token: result.access_token,
            refresh_token: Some(result.refresh_token),
            expires_at: result.expires_at,
        })
    }
}
