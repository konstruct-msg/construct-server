// ============================================================================
// Media Service Types
// ============================================================================

use serde::Serialize;

/// Upload response
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResponse {
    pub media_id: String,
    pub expires_at: u64,
}

/// Error response
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

/// Health check response
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}
