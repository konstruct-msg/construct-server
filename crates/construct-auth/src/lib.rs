use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use construct_config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub jti: String, // JWT ID (unique per token)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    pub iss: String, // Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>, // Device identifier for device-level auth
}

/// JWT Authentication Manager using RS256 (RSA) algorithm only.
///
/// Supports two modes:
/// - **Full mode**: Can sign and verify tokens (requires JWT_PRIVATE_KEY + JWT_PUBLIC_KEY)
/// - **Verify-only mode**: Can only verify tokens (requires JWT_PUBLIC_KEY only)
pub struct AuthManager {
    /// Encoding key (RSA private key) - None for verify-only mode
    encoding_key: Option<EncodingKey>,
    /// Decoding key (RSA public key)
    decoding_key: DecodingKey,
    /// Access token TTL in hours (for REST API)
    access_token_ttl_hours: i64,
    /// Session TTL in days (legacy, kept for backward compatibility)
    #[allow(dead_code)]
    session_ttl_days: i64,
    /// Refresh token TTL in days
    refresh_token_ttl_days: i64,
    /// JWT issuer claim
    issuer: String,
}

impl AuthManager {
    pub fn new(config: &Config) -> Result<Self> {
        // Helper to check if a key string is valid (not empty, not whitespace-only)
        let is_valid_key = |key: &Option<String>| -> bool {
            key.as_ref().map(|k| !k.trim().is_empty()).unwrap_or(false)
        };

        let has_private_key = is_valid_key(&config.jwt_private_key);
        let has_public_key = is_valid_key(&config.jwt_public_key);

        // RS256 requires at least a public key
        if !has_public_key {
            anyhow::bail!(
                "JWT_PUBLIC_KEY is required. Set either:\n\
                - JWT_PUBLIC_KEY only (for verify-only mode, e.g. user-service)\n\
                - JWT_PRIVATE_KEY + JWT_PUBLIC_KEY (for full mode, e.g. auth-service)"
            );
        }

        let public_key = config.jwt_public_key.as_ref().unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
            .context("Failed to parse JWT_PUBLIC_KEY as RSA PEM")?;

        let encoding_key = if has_private_key {
            let private_key = config.jwt_private_key.as_ref().unwrap();
            let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
                .context("Failed to parse JWT_PRIVATE_KEY as RSA PEM")?;
            tracing::info!("JWT RS256 initialized (full mode: can sign and verify)");
            Some(key)
        } else {
            tracing::info!("JWT RS256 initialized (verify-only mode)");
            None
        };

        Ok(Self {
            encoding_key,
            decoding_key,
            access_token_ttl_hours: config.access_token_ttl_hours,
            session_ttl_days: config.session_ttl_days,
            refresh_token_ttl_days: config.refresh_token_ttl_days,
            issuer: config.jwt_issuer.clone(),
        })
    }

    /// Create access token (short-lived, for REST API)
    /// Returns error if AuthManager is in verify-only mode
    pub fn create_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        self.create_token_for_device(user_id, None)
    }

    /// Create access token for a specific device
    /// Returns error if AuthManager is in verify-only mode
    pub fn create_token_for_device(
        &self,
        user_id: &Uuid,
        device_id: Option<&str>,
    ) -> Result<(String, String, i64)> {
        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Cannot create tokens: verify-only mode (no JWT_PRIVATE_KEY)")
        })?;

        let now = Utc::now();
        let exp = now + Duration::hours(self.access_token_ttl_hours);
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: user_id.to_string(),
            jti: jti.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
            device_id: device_id.map(String::from),
        };

        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, encoding_key).context("Failed to encode JWT token")?;

        Ok((token, jti, exp.timestamp()))
    }

    /// Create refresh token (long-lived, for token refresh)
    /// Returns error if AuthManager is in verify-only mode
    pub fn create_refresh_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        self.create_refresh_token_for_device(user_id, None)
    }

    /// Create refresh token for a specific device
    /// Returns error if AuthManager is in verify-only mode
    pub fn create_refresh_token_for_device(
        &self,
        user_id: &Uuid,
        device_id: Option<&str>,
    ) -> Result<(String, String, i64)> {
        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Cannot create tokens: verify-only mode (no JWT_PRIVATE_KEY)")
        })?;

        let now = Utc::now();
        let exp = now + Duration::days(self.refresh_token_ttl_days);
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: user_id.to_string(),
            jti: jti.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
            device_id: device_id.map(String::from),
        };

        let header = Header::new(Algorithm::RS256);
        let token =
            encode(&header, &claims, encoding_key).context("Failed to encode JWT refresh token")?;

        Ok((token, jti, exp.timestamp()))
    }

    /// Verify JWT token (RS256 only)
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        // Check token algorithm
        let header = decode_header(token).context("Failed to decode JWT header")?;

        if header.alg != Algorithm::RS256 {
            anyhow::bail!(
                "Unsupported JWT algorithm: {:?}. Only RS256 is supported.",
                header.alg
            );
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .context("JWT verification failed")?;

        Ok(token_data.claims)
    }

    /// Verify that the device_id from header matches the device_id in JWT claims.
    /// Returns the device_id if verification succeeds.
    /// Returns error if:
    /// - Header device_id is missing
    /// - Claims device_id is missing (token was created without device_id)
    /// - Header device_id doesn't match claims device_id
    pub fn verify_device_id(&self, header_device_id: &str, claims: &Claims) -> Result<String> {
        let claims_device_id = claims
            .device_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Token missing device_id claim"))?;

        if header_device_id != claims_device_id {
            anyhow::bail!(
                "x-device-id header '{}' does not match token device_id '{}'",
                header_device_id,
                claims_device_id
            );
        }

        Ok(header_device_id.to_string())
    }
}

// Unit tests (includes embedded RSA test keys that are NOT secret)
#[cfg(test)]
mod auth_tests;

// Note: test RSA keys in tests.rs are generated solely for testing.
// They must never be used in any real deployment.
