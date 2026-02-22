// ============================================================================
// Capabilities Routes
// ============================================================================
//
// Endpoints:
// - GET /api/v1/users/:id/capabilities - Get user's crypto capabilities
//
// Purpose: Crypto-agility protocol negotiation (Phase 5)
// Allows clients to discover which protocol version and crypto suites a user supports.
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use construct_db;
use construct_error::AppError;
use crypto_agility::{CryptoSuite, ProtocolVersion};

/// GET /api/v1/users/:id/capabilities
///
/// Returns the user's crypto capabilities for protocol negotiation.
/// This is PUBLIC information (no authentication required) because
/// clients need to know the capabilities before establishing encrypted sessions.
///
/// Response:
/// ```json
/// {
///   "user_id": "uuid",
///   "protocol_version": 1,  // 1=Classic, 2=HybridPQ
///   "crypto_suites": ["0x01"]  // Supported cipher suites
/// }
/// ```
pub async fn get_user_capabilities(
    State(app_context): State<Arc<AppContext>>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    // Get user capabilities from database
    let capabilities = construct_db::get_user_capabilities(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "Failed to get user capabilities"
            );
            // anyhow::Error -> AppError conversion (use Validation for database errors)
            AppError::Validation(format!("Failed to fetch user capabilities: {}", e))
        })?;

    match capabilities {
        Some(caps) => {
            // Convert to API response format
            let protocol_version = match caps.protocol_version {
                ProtocolVersion::V1Classic => 1,
                ProtocolVersion::V2HybridPQ => 2,
            };

            let crypto_suites: Vec<String> = caps
                .crypto_suites
                .iter()
                .map(|suite| match suite {
                    CryptoSuite::ClassicX25519 => "0x01".to_string(),
                    CryptoSuite::HybridKyber1024X25519 => "0x02".to_string(),
                })
                .collect();

            Ok((
                StatusCode::OK,
                Json(json!({
                    "user_id": caps.user_id,
                    "protocol_version": protocol_version,
                    "crypto_suites": crypto_suites
                })),
            ))
        }
        None => {
            // User not found
            tracing::debug!(user_id = %user_id, "User not found");
            Err(AppError::Validation(format!("User {} not found", user_id)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_endpoint_compiles() {
        // Verify function signature is correct
        let _ = get_user_capabilities;
    }
}
