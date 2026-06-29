use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use ed25519_compact::{PublicKey, SecretKey, Signature};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use construct_config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub jti: String, // JWT/PASETO ID (unique per token)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    pub iss: String, // Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>, // Device identifier for device-level auth
}

/// Token issuance / verification manager supporting both legacy RS256 JWT and
/// PASETO v4.public (Ed25519).
///
/// Migration strategy (dual-stack):
/// - `verify_token` accepts **both** formats — chosen by token prefix
///   (`v4.public.` → PASETO, otherwise → legacy RS256 JWT).
/// - `create_token*` / `create_refresh_token*` issue the format configured by
///   `Config::token_issue_format` (`"paseto"` target, `"jwt"` legacy transitional).
/// - Legacy JWT paths are removable after the rotation window completes
///   (see `decisions/paseto-v4-public-migration.md`).
///
/// Two modes:
/// - **Full mode**: can sign and verify (private + public keys loaded).
/// - **Verify-only mode**: can only verify (public key only).
pub struct AuthManager {
    // ── Legacy RS256 JWT — optional, retained for dual-stack verify ──────────
    /// JWT encoding key (RSA private key) — None in verify-only mode or after Phase 4 cleanup.
    jwt_encoding_key: Option<EncodingKey>,
    /// JWT decoding key (RSA public key) — None if legacy verify disabled.
    jwt_decoding_key: Option<DecodingKey>,

    // ── PASETO v4.public (Ed25519) — primary post-migration ──────────────────
    /// Ed25519 secret key for PASETO signing — None in verify-only mode.
    paseto_signing_key: Option<SecretKey>,
    /// Ed25519 public key for PASETO verification — None if PASETO verify disabled.
    paseto_verifying_key: Option<PublicKey>,

    // ── Sign policy ───────────────────────────────────────────────────────────
    /// Token format to issue on `create_token*` / `create_refresh_token*`.
    issue_format: TokenFormat,

    // ── TTLs / issuer ─────────────────────────────────────────────────────────
    access_token_ttl_hours: i64,
    #[allow(dead_code)]
    session_ttl_days: i64,
    refresh_token_ttl_days: i64,
    /// Issuer claim (shared by JWT `iss` and PASETO `iss`).
    issuer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenFormat {
    Paseto,
    Jwt,
}

impl TokenFormat {
    fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "paseto" => Ok(TokenFormat::Paseto),
            "jwt" => Ok(TokenFormat::Jwt),
            other => anyhow::bail!(
                "Unknown TOKEN_ISSUE_FORMAT={:?}. Expected \"paseto\" or \"jwt\".",
                other
            ),
        }
    }
}

/// PASETO v4.public header literal (ASCII).
const PASETO_V4_PUBLIC_HEADER: &str = "paseto.v4.public.";
/// Minimum payload size: nonce(32) + signature(64). Message must be > 0.
const PASETO_MIN_PAYLOAD_LEN: usize = 32 + 64;

impl AuthManager {
    pub fn new(config: &Config) -> Result<Self> {
        let is_valid_key = |key: &Option<String>| -> bool {
            key.as_ref().map(|k| !k.trim().is_empty()).unwrap_or(false)
        };

        // ── Load PASETO Ed25519 keys (primary) ──────────────────────────────
        let has_paseto_public = is_valid_key(&config.paseto_public_key);
        let has_paseto_private = is_valid_key(&config.paseto_private_key);

        let (paseto_verifying_key, paseto_signing_key) = if has_paseto_public {
            let pub_pem = config.paseto_public_key.as_ref().unwrap();
            let verifying = PublicKey::from_pem(pub_pem)
                .context("Failed to parse PASETO_PUBLIC_KEY as Ed25519 PEM")?;
            let signing = if has_paseto_private {
                let priv_pem = config.paseto_private_key.as_ref().unwrap();
                let sk = SecretKey::from_pem(priv_pem)
                    .context("Failed to parse PASETO_PRIVATE_KEY as Ed25519 PEM")?;
                tracing::info!("PASETO v4.public initialized (full mode: can sign and verify)");
                Some(sk)
            } else {
                tracing::info!("PASETO v4.public initialized (verify-only mode)");
                None
            };
            (Some(verifying), signing)
        } else {
            (None, None)
        };

        // ── Load legacy JWT RS256 keys (dual-stack verify) ───────────────────
        let has_jwt_public = is_valid_key(&config.jwt_public_key);
        let has_jwt_private = is_valid_key(&config.jwt_private_key);

        let (jwt_decoding_key, jwt_encoding_key) = if has_jwt_public {
            let pub_pem = config.jwt_public_key.as_ref().unwrap();
            let dk = DecodingKey::from_rsa_pem(pub_pem.as_bytes())
                .context("Failed to parse JWT_PUBLIC_KEY as RSA PEM")?;
            let ek = if has_jwt_private {
                let priv_pem = config.jwt_private_key.as_ref().unwrap();
                let ek = EncodingKey::from_rsa_pem(priv_pem.as_bytes())
                    .context("Failed to parse JWT_PRIVATE_KEY as RSA PEM")?;
                tracing::info!("JWT RS256 initialized (legacy dual-stack, full mode)");
                Some(ek)
            } else {
                tracing::info!("JWT RS256 initialized (legacy dual-stack, verify-only mode)");
                None
            };
            (Some(dk), ek)
        } else {
            (None, None)
        };

        // At least one verifying key must be present so verify_token can run.
        if paseto_verifying_key.is_none() && jwt_decoding_key.is_none() {
            anyhow::bail!(
                "No auth keys configured. Set one of:\n\
                 - PASETO_PUBLIC_KEY (+optional PASETO_PRIVATE_KEY) for PASETO v4.public\n\
                 - JWT_PUBLIC_KEY (+optional JWT_PRIVATE_KEY) for legacy RS256\n\
                 Both can be set for dual-stack verify during migration."
            );
        }

        // Sign policy: which format to issue on `create_token*`.
        // We accept either format regardless of which signing keys are loaded — a
        // verify-only deployment (no private key) sets TOKEN_ISSUE_FORMAT=paseto
        // and simply never calls `create_token`. If a caller does call `create_token*
        // without a matching signing key, the call fails at runtime inside `sign_*`.
        let issue_format = TokenFormat::parse(&config.token_issue_format)?;

        Ok(Self {
            jwt_encoding_key,
            jwt_decoding_key,
            paseto_signing_key,
            paseto_verifying_key,
            issue_format,
            access_token_ttl_hours: config.access_token_ttl_hours,
            session_ttl_days: config.session_ttl_days,
            refresh_token_ttl_days: config.refresh_token_ttl_days,
            issuer: config.jwt_issuer.clone(),
        })
    }

    // ── Token creation ─────────────────────────────────────────────────────────

    /// Create access token (short-lived, for REST API).
    /// Returns error if AuthManager cannot sign in the configured format.
    pub fn create_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        self.create_token_for_device(user_id, None)
    }

    /// Create access token for a specific device.
    /// Returns (token, jti, exp). Issues whichever format `issue_format` dictates.
    pub fn create_token_for_device(
        &self,
        user_id: &Uuid,
        device_id: Option<&str>,
    ) -> Result<(String, String, i64)> {
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

        let token = match self.issue_format {
            TokenFormat::Paseto => self.sign_paseto(&claims)?,
            TokenFormat::Jwt => self.sign_jwt(&claims)?,
        };

        Ok((token, jti, exp.timestamp()))
    }

    /// Create refresh token (long-lived, for token refresh).
    pub fn create_refresh_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        self.create_refresh_token_for_device(user_id, None)
    }

    /// Create refresh token for a specific device.
    pub fn create_refresh_token_for_device(
        &self,
        user_id: &Uuid,
        device_id: Option<&str>,
    ) -> Result<(String, String, i64)> {
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

        let token = match self.issue_format {
            TokenFormat::Paseto => self.sign_paseto(&claims)?,
            TokenFormat::Jwt => self.sign_jwt(&claims)?,
        };

        Ok((token, jti, exp.timestamp()))
    }

    // ── Token verification (dual-stack) ────────────────────────────────────────

    /// Verify a token, accepting either PASETO v4.public or legacy RS256 JWT.
    /// Returns the parsed `Claims` on success, error on invalid/expired/unsupported.
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        if token.starts_with("v4.public.") {
            self.verify_paseto(token)
        } else {
            self.verify_jwt(token)
        }
    }

    /// Verify that the device_id from header matches the device_id in token claims.
    /// Same logic for both formats — works on parsed `Claims`.
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

    // ── PASETO v4.public internals ────────────────────────────────────────────
    //
    // Wire format: "v4.public." + base64url(nonce || message || signature)
    //              + optional ".base64url(footer)"     (footer unused for auth tokens)
    // Pre-auth encoding (what Ed25519 signs): "paseto.v4.public." || nonce || message || footer
    // Message = JSON-serialized `Claims`.
    // Nonce   = 32 random bytes (must not repeat for a given key; random is sufficient).
    // Signature = Ed25519 over pre-auth encoding, 64 bytes.

    fn sign_paseto(&self, claims: &Claims) -> Result<String> {
        let sk = self
            .paseto_signing_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Cannot sign PASETO: no private key (verify-only)"))?;

        let message = serde_json::to_vec(claims).context("Failed to serialize PASETO claims")?;

        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Pre-auth encoding: header literal + nonce + message (footer empty).
        let mut pre_auth = Vec::with_capacity(PASETO_V4_PUBLIC_HEADER.len() + 32 + message.len());
        pre_auth.extend_from_slice(PASETO_V4_PUBLIC_HEADER.as_bytes());
        pre_auth.extend_from_slice(&nonce);
        pre_auth.extend_from_slice(&message);

        // Deterministic Ed25519 sign — the nonce embedded in the payload already
        // guarantees signature uniqueness for a given (key, message). No external
        // noise needed, which keeps the signature reproducible by construction.
        let signature = sk.sign(&pre_auth, None);

        let mut payload = Vec::with_capacity(32 + message.len() + 64);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&message);
        payload.extend_from_slice(signature.as_ref());

        Ok(format!("v4.public.{}", URL_SAFE_NO_PAD.encode(&payload)))
    }

    fn verify_paseto(&self, token: &str) -> Result<Claims> {
        let pk = self.paseto_verifying_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("PASETO token presented but no PASETO_PUBLIC_KEY configured")
        })?;

        let stripped = token
            .strip_prefix("v4.public.")
            .ok_or_else(|| anyhow::anyhow!("Malformed PASETO token: missing v4.public. prefix"))?;
        let (payload_b64, _footer_b64) = stripped.split_once('.').unwrap_or((stripped, ""));

        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .context("Failed to base64url-decode PASETO payload")?;

        if payload.len() < PASETO_MIN_PAYLOAD_LEN {
            anyhow::bail!("PASETO payload too short: {} bytes", payload.len());
        }

        let nonce = &payload[..32];
        let signature_bytes = &payload[payload.len() - 64..];
        let message = &payload[32..payload.len() - 64];

        if message.is_empty() {
            anyhow::bail!("PASETO message is empty");
        }

        let mut pre_auth = Vec::with_capacity(PASETO_V4_PUBLIC_HEADER.len() + 32 + message.len());
        pre_auth.extend_from_slice(PASETO_V4_PUBLIC_HEADER.as_bytes());
        pre_auth.extend_from_slice(nonce);
        pre_auth.extend_from_slice(message);

        let signature = Signature::from_slice(signature_bytes)
            .context("Failed to parse PASETO signature (expected 64 bytes)")?;

        pk.verify(&pre_auth, &signature)
            .map_err(|e| anyhow::anyhow!("PASETO signature verification failed: {e}"))?;

        let claims: Claims =
            serde_json::from_slice(message).context("Failed to parse PASETO claims JSON")?;

        self.validate_claims(&claims)?;
        Ok(claims)
    }

    // ── Legacy RS256 JWT internals (removable after Phase 4) ──────────────────

    fn sign_jwt(&self, claims: &Claims) -> Result<String> {
        let encoding_key = self.jwt_encoding_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Cannot sign JWT: verify-only mode (no JWT_PRIVATE_KEY)")
        })?;
        let header = Header::new(Algorithm::RS256);
        encode(&header, claims, encoding_key).context("Failed to encode JWT token")
    }

    fn verify_jwt(&self, token: &str) -> Result<Claims> {
        let decoding_key = self.jwt_decoding_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("JWT token presented but no JWT_PUBLIC_KEY configured")
        })?;

        let header = decode_header(token).context("Failed to decode JWT header")?;
        if header.alg != Algorithm::RS256 {
            anyhow::bail!(
                "Unsupported JWT algorithm: {:?}. Only RS256 is supported.",
                header.alg
            );
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        // jsonwebtoken has 60s default leeway on exp — we keep that to tolerate clock skew.

        let token_data = decode::<Claims>(token, decoding_key, &validation)
            .context("JWT verification failed")?;

        Ok(token_data.claims)
    }

    // ── Shared claim validation (used by PASETO verify; JWT path uses jsonwebtoken's) ──

    fn validate_claims(&self, claims: &Claims) -> Result<()> {
        if claims.iss != self.issuer {
            anyhow::bail!(
                "Token issuer mismatch: expected {:?}, got {:?}",
                self.issuer,
                claims.iss
            );
        }
        let now = Utc::now().timestamp();
        if claims.exp <= now {
            anyhow::bail!("Token expired (exp={}, now={})", claims.exp, now);
        }
        Ok(())
    }
}

// Unit tests (keypairs generated on the fly — no keys committed to the repo).
#[cfg(test)]
mod auth_tests;

// Note: legacy tests previously embedded a fixed RSA key pair (2048-bit) here.
// That pair leaked into the repo history. The current test module generates
// Ed25519 / RSA keypairs at runtime — never committed to source control.
