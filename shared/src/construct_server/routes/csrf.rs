// ============================================================================
// CSRF Protection Module
// ============================================================================
//
// Implements Cross-Site Request Forgery protection using:
// - Double Submit Cookie pattern (for web clients)
// - Origin/Referer header validation
// - Custom header requirement for mobile/API clients
//
// Token Format: base64(timestamp:user_id:hmac_signature)
// - timestamp: Unix timestamp for TTL validation
// - user_id: Bound to specific user session
// - hmac_signature: HMAC-SHA256(timestamp:user_id, secret)
//
// ============================================================================

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, header::SET_COOKIE},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::context::AppContext;
use crate::routes::extractors::TrustedUser;
use construct_config::CsrfConfig;
use construct_error::AppError;

type HmacSha256 = Hmac<Sha256>;

/// Generate a CSRF token for the given user
///
/// Token format: base64(timestamp:user_id:signature)
/// - timestamp: Current Unix timestamp
/// - user_id: User's UUID
/// - signature: HMAC-SHA256 of "timestamp:user_id"
pub fn generate_csrf_token(config: &CsrfConfig, user_id: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Create HMAC signature
    let message = format!("{}:{}", timestamp, user_id);
    let mut mac = HmacSha256::new_from_slice(config.secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_hex = hex::encode(signature);

    // Encode token: timestamp:user_id:signature
    let token_data = format!("{}:{}:{}", timestamp, user_id, signature_hex);
    BASE64.encode(token_data.as_bytes())
}

/// Validate a CSRF token
///
/// Checks:
/// 1. Token format is valid
/// 2. Timestamp is within TTL
/// 3. User ID matches
/// 4. HMAC signature is valid
pub fn validate_csrf_token(
    config: &CsrfConfig,
    token: &str,
    expected_user_id: &str,
) -> Result<(), String> {
    // Decode base64
    let token_bytes = BASE64.decode(token).map_err(|_| "Invalid token encoding")?;

    let token_str = String::from_utf8(token_bytes).map_err(|_| "Invalid token encoding")?;

    // Parse token parts: timestamp:user_id:signature
    let parts: Vec<&str> = token_str.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }

    let timestamp: u64 = parts[0].parse().map_err(|_| "Invalid timestamp")?;
    let user_id = parts[1];
    let signature_hex = parts[2];

    // Check TTL
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now - timestamp > config.token_ttl_secs {
        return Err("Token expired".to_string());
    }

    // Check user ID
    if user_id != expected_user_id {
        return Err("Token user mismatch".to_string());
    }

    // Verify HMAC signature
    let message = format!("{}:{}", timestamp, user_id);
    let mut mac = HmacSha256::new_from_slice(config.secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let expected_signature = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected_signature);

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    if !bool::from(signature_hex.as_bytes().ct_eq(expected_hex.as_bytes())) {
        return Err("Invalid token signature".to_string());
    }

    Ok(())
}

/// Check if the Origin header matches allowed origins
pub fn validate_origin(
    headers: &HeaderMap,
    instance_domain: &str,
    allowed_origins: &[String],
) -> bool {
    // Get Origin header first (preferred)
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Fall back to Referer header (extract origin from URL)
    let origin = origin.or_else(|| {
        headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .and_then(|referer| {
                // Extract origin from referer URL (scheme://host:port)
                // Format: https://example.com/path -> https://example.com
                if let Some(scheme_end) = referer.find("://") {
                    let after_scheme = &referer[scheme_end + 3..];
                    if let Some(path_start) = after_scheme.find('/') {
                        Some(referer[..scheme_end + 3 + path_start].to_string())
                    } else {
                        Some(referer.to_string())
                    }
                } else {
                    None
                }
            })
    });

    match origin {
        Some(ref origin_str) => {
            // Check against instance domain
            if origin_str.contains(instance_domain) {
                return true;
            }

            // Check against allowed origins
            for allowed in allowed_origins {
                if origin_str == allowed || origin_str.starts_with(allowed) {
                    return true;
                }
            }

            false
        }
        None => {
            // No Origin/Referer header - could be mobile app or API client
            // Allow if it has Authorization header (API client)
            // or X-Requested-With header (mobile app)
            true // Will be checked by other means
        }
    }
}

/// Check if request appears to be from a browser
/// Browsers typically send Accept header with text/html
pub fn is_browser_request(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|accept| accept.contains("text/html"))
        .unwrap_or(false)
}

/// Check if request has custom header (indicates non-browser client)
/// Mobile apps should send X-Requested-With header
pub fn has_custom_header(headers: &HeaderMap) -> bool {
    headers.contains_key("x-requested-with")
}

/// Extract CSRF token from request (header or cookie)
pub fn extract_csrf_token(
    headers: &HeaderMap,
    header_name: &str,
    cookie_name: &str,
) -> Option<String> {
    // First try header
    if let Some(token) = headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        return Some(token);
    }

    // Then try cookie
    if let Some(cookies) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for cookie in cookies.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix(&format!("{}=", cookie_name)) {
                return Some(value.to_string());
            }
        }
    }

    None
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// GET /api/csrf-token
/// Returns a new CSRF token for the authenticated user
/// Also sets it as a cookie for Double Submit Cookie pattern
pub async fn get_csrf_token(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user_id.to_string();
    let token = generate_csrf_token(&app_context.config.csrf, &user_id);

    // Build cookie value with security attributes
    let is_https = true; // Assume HTTPS in production
    let cookie_value = if is_https {
        format!(
            "{}={}; SameSite=Strict; Secure; HttpOnly; Path=/; Max-Age={}",
            app_context.config.csrf.cookie_name, token, app_context.config.csrf.token_ttl_secs
        )
    } else {
        format!(
            "{}={}; SameSite=Strict; HttpOnly; Path=/; Max-Age={}",
            app_context.config.csrf.cookie_name, token, app_context.config.csrf.token_ttl_secs
        )
    };

    let mut response = Json(json!({
        "csrf_token": token,
        "expires_in": app_context.config.csrf.token_ttl_secs,
    }))
    .into_response();

    // Set cookie header
    if let Ok(header_value) = HeaderValue::from_str(&cookie_value) {
        response.headers_mut().insert(SET_COOKIE, header_value);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CsrfConfig {
        CsrfConfig {
            enabled: true,
            secret: "test_secret_at_least_32_characters_long".to_string(),
            token_ttl_secs: 3600,
            allowed_origins: vec!["https://example.com".to_string()],
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
        }
    }

    #[test]
    fn test_generate_and_validate_token() {
        let config = test_config();
        let user_id = "test-user-123";

        let token = generate_csrf_token(&config, user_id);
        assert!(!token.is_empty());

        // Should validate successfully
        let result = validate_csrf_token(&config, &token, user_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_user_id() {
        let config = test_config();
        let user_id = "test-user-123";
        let wrong_user_id = "wrong-user-456";

        let token = generate_csrf_token(&config, user_id);

        // Should fail with wrong user ID
        let result = validate_csrf_token(&config, &token, wrong_user_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn test_expired_token() {
        let mut config = test_config();
        // Set TTL to 1 second so we can test expiration
        config.token_ttl_secs = 1;

        let user_id = "test-user-123";
        let token = generate_csrf_token(&config, user_id);

        // Wait for token to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should fail due to expiration
        let result = validate_csrf_token(&config, &token, user_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_invalid_token_format() {
        let config = test_config();
        let user_id = "test-user-123";

        // Invalid base64
        let result = validate_csrf_token(&config, "not-valid-base64!!!", user_id);
        assert!(result.is_err());

        // Invalid format (missing parts)
        let invalid_token = BASE64.encode("just-one-part");
        let result = validate_csrf_token(&config, &invalid_token, user_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        use subtle::ConstantTimeEq;
        assert!(bool::from("abc".as_bytes().ct_eq("abc".as_bytes())));
        assert!(!bool::from("abc".as_bytes().ct_eq("abd".as_bytes())));
        assert!(!bool::from("abc".as_bytes().ct_eq("ab".as_bytes())));
        assert!(!bool::from("".as_bytes().ct_eq("a".as_bytes())));
    }
}
