// ============================================================================
// Keys Handlers for WebSocket
// ============================================================================
//
// NOTE: HTTP handlers for keys have been migrated to src/routes/keys.rs
// This file only contains WebSocket-specific handlers.
//
// ============================================================================

use crate::context::AppContext;
use crate::db;
use construct_crypto::UploadableKeyBundle;
use crate::handlers::connection::ConnectionHandler;
use construct_types::{PublicKeyBundleData, ServerMessage};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;

/// Helper function to extract PublicKeyBundleData from UploadableKeyBundle
/// Decodes the bundle_data and extracts the first cipher suite's keys
fn extract_first_suite_data(
    bundle: &UploadableKeyBundle,
    username: &str,
) -> Result<PublicKeyBundleData, String> {
    // 1. Decode bundle_data from base64
    let bundle_data_bytes = BASE64
        .decode(&bundle.bundle_data)
        .map_err(|_| "Invalid base64 in bundle_data".to_string())?;

    // 2. Decode protobuf to get BundleData
    let bundle_data: construct_crypto::BundleData =
        prost::Message::decode(bundle_data_bytes.as_slice())
            .map_err(|e| format!("Invalid protobuf in bundle_data: {}", e))?;

    // 3. Get the first suite (suite_id = 1, CLASSIC_X25519)
    let first_suite = bundle_data
        .supported_suites
        .first()
        .ok_or("No cipher suites in bundle".to_string())?;

    // 4. Return data in the format expected by WebSocket clients
    // ✅ FIX: Use signed_prekey_signature from suite, not bundle.signature
    // bundle.signature is for bundleData canonical bytes (JSON for deterministic signing), not for signedPrekey
    Ok(PublicKeyBundleData {
        user_id: bundle_data.user_id,
        username: username.to_string(),
        identity_public: first_suite.identity_key.clone(),
        signed_prekey_public: first_suite.signed_prekey.clone(),
        signature: first_suite.signed_prekey_signature.clone(),
        verifying_key: bundle.master_identity_key.clone(),
    })
}

pub async fn handle_get_public_key(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    user_id: String,
) {
    let uuid = match Uuid::parse_str(&user_id) {
        Ok(u) => u,
        Err(_) => {
            handler
                .send_error("INVALID_USER_ID", "Invalid user ID format")
                .await;
            return;
        }
    };

    match crate::db::get_key_bundle(&ctx.db_pool, &uuid).await {
        Ok(Some((bundle, username))) => {
            match extract_first_suite_data(&bundle, &username) {
                Ok(data) => {
                    let response = ServerMessage::PublicKeyBundle(data);
                    if handler.send_msgpack(&response).await.is_err() {
                        // client disconnected
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to extract suite data from key bundle");
                    handler
                        .send_error("INVALID_BUNDLE", "Invalid key bundle format")
                        .await;
                }
            }
        }
        Ok(None) => {
            // SECURITY: Don't reveal whether user exists - use generic error
            handler.send_error("KEY_BUNDLE_UNAVAILABLE", "Key bundle not available").await;
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get user key bundle");
            handler
                .send_error("SERVER_ERROR", "Failed to get user key bundle")
                .await;
        }
    }
}
