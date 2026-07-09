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
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use hkdf::Hkdf;
    use rand::RngExt;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    fn random_bytes32() -> [u8; 32] {
        let mut b = [0u8; 32];
        rand::rng().fill(&mut b);
        b
    }

    fn hash_to_ristretto(data: &[u8; 32]) -> RistrettoPoint {
        use sha2_dalek_compat::{Digest, Sha512};

        let mut h = Sha512::new();
        h.update(data);
        RistrettoPoint::from_hash(h)
    }

    fn derive_token(n_compressed: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
        let ikm: Vec<u8> = n_compressed.iter().chain(nonce.iter()).copied().collect();
        let hk = Hkdf::<sha2::Sha512>::new(None, &ikm);
        let mut out = [0u8; 32];
        hk.expand(b"ConstructPP-v1", &mut out).unwrap();
        out
    }

    fn issue_client_token(token_issuer_key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
        let k = Scalar::from_bytes_mod_order(*token_issuer_key);
        let t = hash_to_ristretto(nonce);
        let r = Scalar::from_bytes_mod_order(random_bytes32());
        let blinded = r * t;
        let z = k * blinded;
        let n = r.invert() * z;
        derive_token(&n.compress().to_bytes(), nonce)
    }

    fn seal_token_for_server(token: &[u8; 32], server_secret: &X25519StaticSecret) -> Vec<u8> {
        let server_pub = X25519PublicKey::from(server_secret);
        let ephemeral_secret = X25519StaticSecret::from(random_bytes32());
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(&server_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(b"construct-token-seal-v1", &mut sym_key).unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
        let nonce_bytes = random_bytes32();
        let aead_nonce = Nonce::from_slice(&nonce_bytes[..12]);
        let ciphertext = cipher.encrypt(aead_nonce, token.as_slice()).unwrap();

        let mut sealed = Vec::with_capacity(32 + 12 + ciphertext.len());
        sealed.extend_from_slice(ephemeral_pub.as_bytes());
        sealed.extend_from_slice(&nonce_bytes[..12]);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

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

    #[tokio::test]
    async fn issued_token_round_trips_through_redemption_and_double_spend_check() {
        let token_issuer_key = random_bytes32();
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let token_nonce = random_bytes32();
        let token = issue_client_token(&token_issuer_key, &token_nonce);
        let sealed_token = seal_token_for_server(&token, &server_secret);

        let opened =
            open_sealed_token_bytes(&sealed_token, &server_secret).expect("sealed token must open");
        let opened_token: [u8; 32] = opened
            .try_into()
            .expect("opened plaintext must be exactly 32 bytes");
        assert_eq!(
            opened_token, token,
            "server must recover the original token bytes"
        );
        assert!(
            verify_token(&opened_token, &token_nonce, &token_issuer_key),
            "issued token must verify on the redemption path before Redis double-spend logic"
        );

        let redis_client =
            redis::Client::open("redis://127.0.0.1:6379").expect("redis client must build");
        let Ok(mut conn) = redis::aio::ConnectionManager::new(redis_client).await else {
            eprintln!(
                "skipping Redis-backed double-spend portion: redis://127.0.0.1:6379 unavailable"
            );
            return;
        };

        let spent_key = format!("spent:{}", hex::encode(Sha256::digest(token_nonce)));
        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .query_async(&mut conn)
            .await
            .expect("test cleanup must succeed");

        let first = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &token_nonce,
            &sealed_token,
        )
        .await;
        assert_eq!(first, TokenRedeemResult::Ok);

        let second = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &token_nonce,
            &sealed_token,
        )
        .await;
        assert_eq!(second, TokenRedeemResult::DoubleSpent);

        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .query_async(&mut conn)
            .await
            .expect("test cleanup must succeed");
    }
}
