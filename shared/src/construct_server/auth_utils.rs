use std::sync::Arc;

use tonic::{Status, metadata::MetadataMap};
use uuid::Uuid;

use construct_auth::AuthManager;

/// Extract authenticated user ID from gRPC request metadata.
///
/// Resolution order:
/// 1. `x-user-id` header — injected by gateway after JWT validation. Trusted.
/// 2. `Authorization: Bearer <JWT>` — direct gRPC connections. Crypto-verified.
///
/// Returns `Status::unauthenticated` if neither is present or valid.
pub fn extract_user_id(
    auth_manager: &Arc<AuthManager>,
    metadata: &MetadataMap,
) -> Result<Uuid, Status> {
    // 1. x-user-id header (gateway-injected, trusted)
    if let Some(uid) = metadata
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(uid);
    }

    // 2. Authorization: Bearer <JWT>
    let token = metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("Missing authentication"))?;

    let claims = auth_manager
        .verify_token(token)
        .map_err(|_| Status::unauthenticated("Invalid or expired token"))?;

    Uuid::parse_str(&claims.sub)
        .map_err(|_| Status::unauthenticated("Invalid user ID in token claims"))
}
