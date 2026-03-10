// ============================================================================
// Messaging Service Handlers
// ============================================================================

use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use std::sync::Arc;
use uuid::Uuid;

use crate::context::MessagingServiceContext;
use crate::core as messaging_core;
use construct_context::AppContext;
use construct_error::AppError;
use construct_extractors::TrustedUser;
use construct_types::api::ConfirmMessageRequest;
use construct_types::message::EndSessionData;

fn app_state(context: &Arc<MessagingServiceContext>) -> State<Arc<AppContext>> {
    State(Arc::new(context.to_app_context()))
}

pub async fn send_control_message(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    headers: HeaderMap,
    Json(data): Json<EndSessionData>,
) -> Result<impl IntoResponse, AppError> {
    messaging_core::send_control_message(
        app_state(&context),
        TrustedUser(user_id),
        headers,
        Json(data),
    )
    .await
}

#[allow(dead_code)]
pub async fn confirm_message(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(data): Json<ConfirmMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = Uuid::parse_str(&user_id.to_string())
        .map_err(|_| AppError::Validation("Invalid authenticated user ID".to_string()))?;
    let result =
        messaging_core::confirm_pending_message(app_state(&context).0, user_id, &data.temp_id)
            .await?;
    Ok((axum::http::StatusCode::OK, Json(result)))
}
