// ============================================================================
// Messaging Service Handlers - Phase 2.6.4
// ============================================================================
//
// Wrapper handlers that convert MessagingServiceContext to AppContext
// for use with existing messaging-related route handlers.
//
// This is a temporary solution until handlers are refactored to use traits.
//
// ============================================================================

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use std::sync::Arc;

use construct_server_shared::e2e::EncryptedMessage;
use construct_server_shared::error::AppError;
use crate::messaging_service::MessagingServiceContext;
use construct_server_shared::routes::extractors::AuthenticatedUser;
use construct_server_shared::routes::messages;

/// Wrapper for send_message handler (POST /api/v1/messages)
pub async fn send_message(
    State(context): State<Arc<MessagingServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(message): Json<EncryptedMessage>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    messages::send_message(State(app_context), user, headers, Json(message)).await
}

/// Wrapper for get_messages handler (GET /api/v1/messages?since=<id>)
pub async fn get_messages(
    State(context): State<Arc<MessagingServiceContext>>,
    user: AuthenticatedUser,
    query: Query<messages::GetMessagesParams>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    messages::get_messages(State(app_context), user, query).await
}
