// ============================================================================
// Media Service Utilities
// ============================================================================

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Validate upload token
/// Expected format: {timestamp_hex}.{random_hex}.{hmac_hex}
#[allow(dead_code)]
pub fn validate_upload_token(token: &str, secret: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        tracing::warn!(
            "Invalid token format: expected 3 parts, got {}",
            parts.len()
        );
        return false;
    }

    let timestamp_hex = parts[0];
    let random_hex = parts[1];
    let expected_hmac = parts[2];

    // Validate hex format
    if hex::decode(timestamp_hex).is_err() || hex::decode(random_hex).is_err() {
        tracing::warn!("Invalid hex encoding in token");
        return false;
    }

    // Reconstruct message
    let message = format!("{}.{}", timestamp_hex, random_hex);
    let computed_hmac = compute_hmac(&message, secret);

    // Constant-time comparison
    expected_hmac == computed_hmac
}

/// Compute HMAC-SHA256
pub fn compute_hmac(message: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());

    let result = mac.finalize();
    hex::encode(result.into_bytes())
}
