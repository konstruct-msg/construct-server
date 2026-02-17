// ============================================================================
// Keys Routes
// ============================================================================
//
// Endpoints:
// - POST /keys/upload - Upload or update user's key bundle (legacy)
// - POST /api/v1/keys/upload - Upload or update user's key bundle [Phase 2.5.4]
// - GET /keys/:user_id - Retrieve user's public key bundle (legacy)
// - GET /api/v1/users/:id/public-key - Retrieve user's public key bundle [Phase 2.5.4]
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::context::AppContext;
use crate::routes::extractors::TrustedUser;
use crate::user_service::core as user_core;
use construct_crypto::UploadableKeyBundle;
use construct_error::AppError;

// ============================================================================
// Public Key Response (Invite Links & QR API Spec)
// ============================================================================

/// Nested key bundle structure for public key response
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6A
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyBundleResponse {
    /// Base64-encoded JSON bundle data (contains cipher suites, keys)
    pub bundle_data: String,
    /// Base64-encoded X25519 identity key (for key exchange/sessions)
    pub master_identity_key: String,
    /// Base64-encoded Ed25519 signature of bundle_data (64 bytes)
    pub signature: String,
}

/// Public key response structure matching the spec
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6A
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    /// Nested key bundle with bundleData and masterIdentityKey
    pub key_bundle: KeyBundleResponse,
    /// Username of the user
    pub username: String,
    /// Base64-encoded Ed25519 verifying key (REQUIRED for invite verification)
    pub verifying_key: String,
}

/// Request body for PATCH /api/v1/users/me/public-key
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6B
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVerifyingKeyRequest {
    /// Base64-encoded Ed25519 verifying key
    pub verifying_key: String,
    /// Optional reason for update (e.g., "invite_signature_mismatch")
    pub reason: Option<String>,
}

/// POST /keys/upload (legacy) or POST /api/v1/keys/upload
/// Uploads or updates a user's key bundle
///
/// Security:
/// - Requires authentication (via Gateway X-User-Id header)
/// - Requires CSRF protection (via middleware)
/// - Requires request signature (Ed25519) if enabled
/// - Replay protection (nonce + timestamp)
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
/// Gateway verifies JWT and propagates user identity via X-User-Id header.
pub async fn upload_keys(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    headers: HeaderMap,
    Json(bundle): Json<UploadableKeyBundle>,
) -> Result<impl IntoResponse, AppError> {
    user_core::upload_keys(app_context, user.0, headers, bundle).await
}

/// GET /keys/:user_id (legacy) or GET /api/v1/users/:id/public-key
/// Retrieves a user's public key bundle
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
pub async fn get_keys(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    Path(user_id_str): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_keys_impl(app_context, user, user_id_str).await
}

/// Internal implementation for get_keys
/// Supports both /keys/:user_id and /api/v1/users/:id/public-key paths
/// Returns response format per INVITE_LINKS_QR_API_SPEC.md Section 6A
async fn get_keys_impl(
    app_context: Arc<AppContext>,
    user: TrustedUser,
    user_id_str: String,
) -> Result<impl IntoResponse, AppError> {
    user_core::get_public_key_bundle(app_context, user.0, user_id_str).await
}

/// GET /api/v1/users/:id/public-key
/// Retrieves a user's public key bundle (REST API endpoint)
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6A
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
pub async fn get_public_key_bundle(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_keys_impl(app_context, user, id).await
}

/// PATCH /api/v1/users/me/public-key
/// Updates the user's verifying key (Ed25519)
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6B
///
/// This endpoint allows updating the Ed25519 verifying key used for invite signatures.
/// Useful when there's a signature mismatch and the client needs to re-sync.
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
pub async fn update_verifying_key(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    headers: HeaderMap,
    Json(request): Json<UpdateVerifyingKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    user_core::update_verifying_key(
        app_context,
        user.0,
        headers,
        user_core::UpdateVerifyingKeyInput {
            verifying_key: request.verifying_key,
            reason: request.reason,
        },
    )
    .await
}
