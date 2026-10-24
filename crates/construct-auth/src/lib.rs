use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use ed25519_compact::{PublicKey, SecretKey, Signature};
use once_cell::sync::Lazy;
use prometheus::{IntCounterVec, opts, register_int_counter_vec};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use construct_config::Config;

/// Counts token verifications by format. Only `format="paseto"` is emitted since 0.20.0
/// (RS256 JWT support was removed); the label is kept so existing dashboards and alerts
/// keep working. A token that is not v4.public is rejected without being counted.
static TOKEN_VERIFY_FORMAT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_auth_token_verify_format_total",
            "Token verifications by format (paseto)"
        ),
        &["format"]
    )
    .expect("Failed to register TOKEN_VERIFY_FORMAT_TOTAL")
});

/// Counts PASETO verifications by which key in the set succeeded ("current" |
/// "previous"). During a key rotation, watch `previous` fall to zero — that is the
/// signal that every token signed by the old key has expired and it can be dropped
/// from `PASETO_PUBLIC_KEY_PREVIOUS`.
static PASETO_VERIFY_KEY_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "construct_auth_paseto_verify_key_total",
            "PASETO verifications by key age (current | previous)"
        ),
        &["key"]
    )
    .expect("Failed to register PASETO_VERIFY_KEY_TOTAL")
});

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub jti: String, // PASETO token ID (unique per token)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    pub iss: String, // Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>, // Device identifier for device-level auth
}

/// Token issuance / verification manager for PASETO v4.public (Ed25519) tokens.
///
/// Since 0.20.0 PASETO v4.public is the only access/refresh token format; legacy RS256
/// JWT issuance and verification were removed. A token without the `v4.public.` prefix is
/// rejected as invalid.
///
/// Two modes:
/// - **Full mode**: can sign and verify (private + public keys loaded).
/// - **Verify-only mode**: can only verify (public key only).
pub struct AuthManager {
    // ── PASETO v4.public (Ed25519) ───────────────────────────────────────────
    /// Ed25519 secret key for PASETO signing — None in verify-only mode.
    paseto_signing_key: Option<SecretKey>,
    /// Ed25519 public key for PASETO verification — None if PASETO verify disabled.
    paseto_verifying_key: Option<PublicKey>,
    /// Previous PASETO verify keys kept active during a rotation overlap window.
    /// Tried after `paseto_verifying_key` so tokens signed by a superseded key still
    /// verify until they expire. Signing always uses the current key only.
    paseto_verifying_keys_previous: Vec<PublicKey>,

    // ── TTLs / issuer ─────────────────────────────────────────────────────────
    access_token_ttl_hours: i64,
    #[allow(dead_code)]
    session_ttl_days: i64,
    refresh_token_ttl_days: i64,
    /// Issuer claim (`iss`) of issued tokens, checked on verify.
    issuer: String,
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

        // ── Previous PASETO verify keys (rotation overlap window) ─────────────
        // Only meaningful when a current verify key is loaded. Parsed strictly: a
        // malformed previous key is a hard error (it would silently drop overlap
        // coverage otherwise). De-dup against the current key so a copy-paste of the
        // current key into the previous list is harmless.
        let mut paseto_verifying_keys_previous: Vec<PublicKey> = Vec::new();
        if let Some(ref current) = paseto_verifying_key {
            let current_bytes: &[u8] = current.as_ref();
            for pem in &config.paseto_public_key_previous {
                let pk = PublicKey::from_pem(pem)
                    .context("Failed to parse PASETO_PUBLIC_KEY_PREVIOUS entry as Ed25519 PEM")?;
                let pk_bytes: &[u8] = pk.as_ref();
                if pk_bytes == current_bytes {
                    continue; // same as current — not a distinct previous key
                }
                if paseto_verifying_keys_previous.iter().any(|e| {
                    let e_bytes: &[u8] = e.as_ref();
                    e_bytes == pk_bytes
                }) {
                    continue; // duplicate entry
                }
                paseto_verifying_keys_previous.push(pk);
            }
            if !paseto_verifying_keys_previous.is_empty() {
                tracing::info!(
                    count = paseto_verifying_keys_previous.len(),
                    "PASETO rotation overlap active — accepting {} previous verify key(s)",
                    paseto_verifying_keys_previous.len()
                );
            }
        } else if !config.paseto_public_key_previous.is_empty() {
            tracing::warn!(
                "PASETO_PUBLIC_KEY_PREVIOUS set but PASETO_PUBLIC_KEY is not — previous keys ignored"
            );
        }

        // A verifying key must be present so verify_token can run.
        if paseto_verifying_key.is_none() {
            anyhow::bail!(
                "No auth keys configured. Set PASETO_PUBLIC_KEY (+ PASETO_PRIVATE_KEY on the \
                 service that issues tokens) for PASETO v4.public."
            );
        }

        Ok(Self {
            paseto_signing_key,
            paseto_verifying_key,
            paseto_verifying_keys_previous,
            access_token_ttl_hours: config.access_token_ttl_hours,
            session_ttl_days: config.session_ttl_days,
            refresh_token_ttl_days: config.refresh_token_ttl_days,
            issuer: config.token_issuer.clone(),
        })
    }

    // ── Token creation ─────────────────────────────────────────────────────────

    /// Create access token (short-lived, for REST API).
    /// Returns error if AuthManager has no signing key (verify-only mode).
    pub fn create_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        self.create_token_for_device(user_id, None)
    }

    /// Create access token for a specific device.
    /// Returns (token, jti, exp).
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

        let token = self.sign_paseto(&claims)?;

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

        let token = self.sign_paseto(&claims)?;

        Ok((token, jti, exp.timestamp()))
    }

    // ── Token verification ────────────────────────────────────────

    /// Verify a PASETO v4.public token.
    /// Returns the parsed `Claims` on success, error on invalid/expired/unsupported
    /// (including any token that is not v4.public).
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        if !token.starts_with("v4.public.") {
            anyhow::bail!("Unsupported token format: expected PASETO v4.public");
        }
        TOKEN_VERIFY_FORMAT_TOTAL
            .with_label_values(&["paseto"])
            .inc();
        self.verify_paseto(token)
    }

    /// Verify that the device_id from header matches the device_id in token claims.
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

        // Try the current verify key first, then any previous keys within the rotation
        // overlap window. Record which key matched so ops can watch `previous` usage
        // fall to zero — the signal that the old key can be removed.
        if pk.verify(&pre_auth, &signature).is_ok() {
            PASETO_VERIFY_KEY_TOTAL
                .with_label_values(&["current"])
                .inc();
        } else if self
            .paseto_verifying_keys_previous
            .iter()
            .any(|prev| prev.verify(&pre_auth, &signature).is_ok())
        {
            PASETO_VERIFY_KEY_TOTAL
                .with_label_values(&["previous"])
                .inc();
        } else {
            anyhow::bail!("PASETO signature verification failed against all active keys");
        }

        let claims: Claims =
            serde_json::from_slice(message).context("Failed to parse PASETO claims JSON")?;

        self.validate_claims(&claims)?;
        Ok(claims)
    }

    // ── Claim validation ──

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
