// ============================================================================
// Sealed Sender — Privacy Pass Token Redemption (stealth-sealed-sender-v2 Phase 1)
// ============================================================================
//
// Redeems the VOPRF token attached to a sealed-sender message
// (`SealedInner.token_nonce` / `token_bytes`) as an anti-abuse gate — this is
// meant to eventually replace sender authentication as the spam control for
// sealed sends (see construct-docs/decisions/stealth-sealed-sender-v2-always-on.md).
//
// Steps:
//   1. Decrypt `token_bytes` (sealed to this server's X25519 token-encryption
//      key by the client) to recover the 32-byte finalized token.
//   2. Verify the token against the server's VOPRF issuer scalar `k` and the
//      plaintext `token_nonce`.
//   3. Double-spend check: `SET spent:{sha256(nonce)} 1 NX EX 30d`. A single
//      key (unlike the two-layer delivery-tag cache in `spent_tag.rs`) is
//      sufficient — this isn't a replay *window* problem, it's spend-once-ever
//      within the TTL.
//
// Enforcement (off/warn/enforce) is applied by the caller in `envelope.rs`;
// this module only reports what happened.
// ============================================================================

use construct_crypto::privacy_pass::{open_sealed_token_bytes, verify_token};
use sha2::{Digest, Sha256};

/// TTL for the double-spend marker (30 days).
const SPENT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Outcome of a token redemption attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRedeemResult {
    /// Token decrypted, verified, and not previously spent.
    Ok,
    /// `token_nonce` or `token_bytes` was empty.
    MissingToken,
    /// `token_bytes` failed to decrypt (wrong key, corrupted, or tampered).
    DecryptFailed,
    /// Decrypted token or nonce was malformed, or failed VOPRF verification.
    InvalidToken,
    /// Nonce was already redeemed (replay / double-spend).
    DoubleSpent,
    /// Redis was unavailable during the double-spend check.
    RedisError,
    /// This instance has no `TOKEN_ISSUER_KEY` / token-encryption secret configured.
    NotConfigured,
}

impl TokenRedeemResult {
    /// Metric label for this outcome.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::MissingToken => "missing_token",
            Self::DecryptFailed => "decrypt_failed",
            Self::InvalidToken => "invalid_token",
            Self::DoubleSpent => "double_spent",
            Self::RedisError => "redis_error",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// Redeem a Privacy Pass token, given this instance's (possibly absent) keys.
/// Returns `NotConfigured` if either key is missing — callers don't need to
/// special-case that themselves.
pub async fn redeem_token_checked(
    conn: &mut redis::aio::ConnectionManager,
    token_issuer_key: Option<&[u8; 32]>,
    server_secret: Option<&x25519_dalek::StaticSecret>,
    token_nonce: &[u8],
    token_bytes: &[u8],
) -> TokenRedeemResult {
    match (token_issuer_key, server_secret) {
        (Some(k), Some(secret)) => redeem_token(conn, k, secret, token_nonce, token_bytes).await,
        _ => TokenRedeemResult::NotConfigured,
    }
}

/// Redeem a Privacy Pass token attached to a sealed-sender message.
async fn redeem_token(
    conn: &mut redis::aio::ConnectionManager,
    token_issuer_key: &[u8; 32],
    server_secret: &x25519_dalek::StaticSecret,
    token_nonce: &[u8],
    token_bytes: &[u8],
) -> TokenRedeemResult {
    if token_nonce.is_empty() || token_bytes.is_empty() {
        return TokenRedeemResult::MissingToken;
    }

    let Ok(nonce): Result<[u8; 32], _> = token_nonce.try_into() else {
        return TokenRedeemResult::InvalidToken;
    };

    let decrypted = match open_sealed_token_bytes(token_bytes, server_secret) {
        Ok(d) => d,
        Err(_) => return TokenRedeemResult::DecryptFailed,
    };

    let Ok(token): Result<[u8; 32], _> = decrypted.try_into() else {
        return TokenRedeemResult::InvalidToken;
    };

    if !verify_token(&token, &nonce, token_issuer_key) {
        return TokenRedeemResult::InvalidToken;
    }

    let key = format!("spent:{}", hex::encode(Sha256::digest(nonce)));
    let set: redis::RedisResult<Option<String>> = redis::cmd("SET")
        .arg(&key)
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(SPENT_TTL_SECS)
        .query_async(conn)
        .await;

    match set {
        Ok(Some(_)) => TokenRedeemResult::Ok,
        Ok(None) => TokenRedeemResult::DoubleSpent,
        Err(_) => TokenRedeemResult::RedisError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct() {
        let all = [
            TokenRedeemResult::Ok,
            TokenRedeemResult::MissingToken,
            TokenRedeemResult::DecryptFailed,
            TokenRedeemResult::InvalidToken,
            TokenRedeemResult::DoubleSpent,
            TokenRedeemResult::RedisError,
            TokenRedeemResult::NotConfigured,
        ];
        let labels: std::collections::HashSet<_> = all.iter().map(|r| r.as_label()).collect();
        assert_eq!(labels.len(), all.len());
    }
}
