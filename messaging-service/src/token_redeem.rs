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
// Logical-message unit (`token_spend_id` + recipient):
//   Multi-chunk E2EE bodies (albums, large media) become many sealed wire
//   envelopes. The economic unit is one *logical* message, not one envelope.
//   Clients put a shared 32-byte `token_spend_id` on every chunk of that
//   message and a Privacy Pass token on the first only. After the first
//   envelope redeems a token we mark
//   `pp:unit:{sha256(spend_id || "|" || recipient_user_id)}` paid; later
//   envelopes with the same spend_id **and** same recipient are accepted
//   without a new spend, up to `MAX_ENVELOPES_PER_SPEND_UNIT` (matches client
//   `maxChunks` = 256). Binding the unit to the recipient is required: spend_id
//   is client-chosen, so without the recipient a single token could cover up to
//   256 envelopes to 256 different users. See construct-docs
//   `backend/TOKEN_SPEND_UNIT_RECIPIENT_BINDING_SPEC.md`.
//
// Enforcement (off/warn/enforce) is applied by the caller in `envelope.rs`;
// this module only reports what happened.
// ============================================================================

use construct_crypto::privacy_pass::{open_sealed_token_bytes, verify_token};
use sha2::{Digest, Sha256};

/// TTL for the double-spend marker (30 days).
const SPENT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// How long a paid `token_spend_id` covers follow-up wire envelopes (2 h).
/// Long enough for slow multi-chunk sends; short enough to bound free rides.
const SPEND_UNIT_TTL_SECS: u64 = 2 * 60 * 60;

/// Max sealed wire envelopes covered by one token after the first redeem.
/// Must stay ≥ client `ChunkedDeliveryConfig.maxChunks` (256).
pub(crate) const MAX_ENVELOPES_PER_SPEND_UNIT: i64 = 256;

/// Expected length of `SealedInner.token_spend_id` when present.
const SPEND_ID_LEN: usize = 32;

/// Outcome of a token redemption attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRedeemResult {
    /// Token decrypted, verified, and not previously spent.
    Ok,
    /// Follow-up envelope covered by a previously paid `token_spend_id` (no new token).
    UnitCovered,
    /// `token_nonce` or `token_bytes` was empty (and no paid spend unit covered this send).
    MissingToken,
    /// `token_bytes` failed to decrypt (wrong key, corrupted, or tampered).
    DecryptFailed,
    /// Decrypted token or nonce was malformed, or failed VOPRF verification.
    InvalidToken,
    /// Nonce was already redeemed (replay / double-spend).
    DoubleSpent,
    /// More than [`MAX_ENVELOPES_PER_SPEND_UNIT`] envelopes used the same `token_spend_id`.
    UnitExhausted,
    /// Redis was unavailable during the double-spend / unit check.
    RedisError,
    /// This instance has no `TOKEN_ISSUER_KEY` / token-encryption secret configured.
    NotConfigured,
}

impl TokenRedeemResult {
    /// Metric label for this outcome.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::UnitCovered => "unit_covered",
            Self::MissingToken => "missing_token",
            Self::DecryptFailed => "decrypt_failed",
            Self::InvalidToken => "invalid_token",
            Self::DoubleSpent => "double_spent",
            Self::UnitExhausted => "unit_exhausted",
            Self::RedisError => "redis_error",
            Self::NotConfigured => "not_configured",
        }
    }

    /// Whether the sealed send is allowed under the token policy (warn/enforce gates).
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Ok | Self::UnitCovered)
    }
}

/// Redeem (or cover) a sealed send's Privacy Pass obligation.
///
/// * `token_spend_id` — optional shared id for a multi-envelope logical message.
///   When a prior envelope already paid for this id **to the same recipient**,
///   returns [`TokenRedeemResult::UnitCovered`] without consuming another token.
/// * `recipient_user_id` — routing address of this envelope; bound into the unit
///   key so a client-chosen `spend_id` cannot cover envelopes to other users.
/// * Empty spend id → legacy per-envelope redemption.
pub async fn redeem_token_checked(
    conn: &mut redis::aio::ConnectionManager,
    token_issuer_key: Option<&[u8; 32]>,
    server_secret: Option<&x25519_dalek::StaticSecret>,
    token_nonce: &[u8],
    token_bytes: &[u8],
    token_spend_id: &[u8],
    recipient_user_id: &str,
) -> TokenRedeemResult {
    match (token_issuer_key, server_secret) {
        (Some(k), Some(secret)) => {
            redeem_for_sealed_send(
                conn,
                k,
                secret,
                token_nonce,
                token_bytes,
                token_spend_id,
                recipient_user_id,
            )
            .await
        }
        _ => TokenRedeemResult::NotConfigured,
    }
}

async fn redeem_for_sealed_send(
    conn: &mut redis::aio::ConnectionManager,
    token_issuer_key: &[u8; 32],
    server_secret: &x25519_dalek::StaticSecret,
    token_nonce: &[u8],
    token_bytes: &[u8],
    token_spend_id: &[u8],
    recipient_user_id: &str,
) -> TokenRedeemResult {
    let spend_id = match normalize_spend_id(token_spend_id) {
        Ok(id) => id,
        Err(()) => return TokenRedeemResult::InvalidToken,
    };

    // Follow-up chunks of a paid logical message: no new token required.
    if let Some(id) = spend_id {
        match try_cover_with_paid_unit(conn, id, recipient_user_id).await {
            UnitLookup::Covered => return TokenRedeemResult::UnitCovered,
            UnitLookup::Exhausted => return TokenRedeemResult::UnitExhausted,
            UnitLookup::NeedToken => {}
            UnitLookup::RedisError => return TokenRedeemResult::RedisError,
        }
    }

    let result = redeem_token(
        conn,
        token_issuer_key,
        server_secret,
        token_nonce,
        token_bytes,
    )
    .await;

    // First envelope of a multi-chunk set: after a successful spend, open the unit
    // so remaining chunks with the same (spend_id, recipient) are covered.
    if result == TokenRedeemResult::Ok
        && let Some(id) = spend_id
        && let Err(()) = open_spend_unit(conn, id, recipient_user_id).await
    {
        // Redis failed after the token was already spent — deliver anyway
        // (fail-open for the unit bookkeeping; next chunks may need tokens).
        tracing::warn!("token spend unit open failed after successful redeem (non-fatal)");
    }

    result
}

enum UnitLookup {
    Covered,
    Exhausted,
    NeedToken,
    RedisError,
}

fn normalize_spend_id(raw: &[u8]) -> Result<Option<&[u8]>, ()> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() != SPEND_ID_LEN {
        return Err(());
    }
    Ok(Some(raw))
}

/// Redis key for a paid logical-message unit.
///
/// Hashes `spend_id || "|" || recipient_user_id` so:
/// - the key is fixed-length regardless of id format, and
/// - the domain separator prevents `(spend_id="…a", user="b…")` colliding with
///   `(spend_id="…ab", user="…")`.
///
/// Recipient binding is the anti-abuse property: without it a client-chosen
/// `spend_id` lets one token cover envelopes to many different users.
fn unit_key(spend_id: &[u8], recipient_user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spend_id);
    hasher.update(b"|");
    hasher.update(recipient_user_id.as_bytes());
    format!("pp:unit:{}", hex::encode(hasher.finalize()))
}

/// If `pp:unit:{h(spend_id|recipient)}` exists and count < max, INCR and return Covered.
async fn try_cover_with_paid_unit(
    conn: &mut redis::aio::ConnectionManager,
    spend_id: &[u8],
    recipient_user_id: &str,
) -> UnitLookup {
    let key = unit_key(spend_id, recipient_user_id);
    // Atomic: only INCR when the key exists and is below the cap.
    // Returns: 1 covered, 0 need token, -1 exhausted.
    let script = redis::Script::new(
        r#"
        local v = redis.call('GET', KEYS[1])
        if not v then
          return 0
        end
        local n = tonumber(v)
        if n == nil then
          return 0
        end
        if n >= tonumber(ARGV[1]) then
          return -1
        end
        redis.call('INCR', KEYS[1])
        return 1
        "#,
    );
    let res: redis::RedisResult<i64> = script
        .key(&key)
        .arg(MAX_ENVELOPES_PER_SPEND_UNIT)
        .invoke_async(conn)
        .await;
    match res {
        Ok(1) => UnitLookup::Covered,
        Ok(-1) => UnitLookup::Exhausted,
        Ok(_) => UnitLookup::NeedToken,
        Err(_) => UnitLookup::RedisError,
    }
}

/// Mark a spend unit as paid with envelope count = 1 (the paying envelope).
async fn open_spend_unit(
    conn: &mut redis::aio::ConnectionManager,
    spend_id: &[u8],
    recipient_user_id: &str,
) -> Result<(), ()> {
    let key = unit_key(spend_id, recipient_user_id);
    // SET NX so a concurrent first-envelope race doesn't reset the counter.
    // If the key already exists, INCR (another paying envelope finished first).
    let script = redis::Script::new(
        r#"
        local ok = redis.call('SET', KEYS[1], 1, 'EX', ARGV[1], 'NX')
        if ok then
          return 1
        end
        redis.call('INCR', KEYS[1])
        return 0
        "#,
    );
    let res: redis::RedisResult<i64> = script
        .key(&key)
        .arg(SPEND_UNIT_TTL_SECS)
        .invoke_async(conn)
        .await;
    match res {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
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
            TokenRedeemResult::UnitCovered,
            TokenRedeemResult::MissingToken,
            TokenRedeemResult::DecryptFailed,
            TokenRedeemResult::InvalidToken,
            TokenRedeemResult::DoubleSpent,
            TokenRedeemResult::UnitExhausted,
            TokenRedeemResult::RedisError,
            TokenRedeemResult::NotConfigured,
        ];
        let labels: std::collections::HashSet<_> = all.iter().map(|r| r.as_label()).collect();
        assert_eq!(labels.len(), all.len());
    }

    #[test]
    fn accept_includes_unit_covered() {
        assert!(TokenRedeemResult::Ok.is_accept());
        assert!(TokenRedeemResult::UnitCovered.is_accept());
        assert!(!TokenRedeemResult::MissingToken.is_accept());
        assert!(!TokenRedeemResult::DoubleSpent.is_accept());
        assert!(!TokenRedeemResult::UnitExhausted.is_accept());
    }

    const RECIPIENT_A: &str = "user-a-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const RECIPIENT_B: &str = "user-b-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    #[test]
    fn normalize_spend_id_rules() {
        assert_eq!(normalize_spend_id(&[]), Ok(None));
        let id = random_bytes32();
        assert_eq!(normalize_spend_id(&id), Ok(Some(id.as_slice())));
        assert!(normalize_spend_id(&[1, 2, 3]).is_err());
    }

    #[test]
    fn unit_key_binds_recipient_and_uses_domain_separator() {
        let spend = [0xABu8; 32];
        let k_a = unit_key(&spend, RECIPIENT_A);
        let k_b = unit_key(&spend, RECIPIENT_B);
        assert_ne!(
            k_a, k_b,
            "same spend_id to different recipients must differ"
        );
        assert!(k_a.starts_with("pp:unit:"));
        assert_eq!(k_a.len(), "pp:unit:".len() + 64);

        // Domain separator: (spend||"|")||recipient must not collide with
        // alternate concatenations that omit the separator.
        let mut spend_with_suffix = spend.to_vec();
        spend_with_suffix.push(b'|');
        spend_with_suffix.extend_from_slice(b"x");
        let alt = unit_key(&spend_with_suffix, &RECIPIENT_A[1..]);
        // Not a formal collision proof, but different inputs must hash differently
        // when recipient prefixes differ via the separator.
        assert_ne!(unit_key(&spend, RECIPIENT_A), alt);
    }

    async fn try_redis() -> Option<redis::aio::ConnectionManager> {
        let redis_client =
            redis::Client::open("redis://127.0.0.1:6379").expect("redis client must build");
        redis::aio::ConnectionManager::new(redis_client).await.ok()
    }

    fn issue_sealed(issuer: &[u8; 32], server_secret: &X25519StaticSecret) -> ([u8; 32], Vec<u8>) {
        let token_nonce = random_bytes32();
        let token = issue_client_token(issuer, &token_nonce);
        let sealed = seal_token_for_server(&token, server_secret);
        (token_nonce, sealed)
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

        let Some(mut conn) = try_redis().await else {
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
            &[],
            RECIPIENT_A,
        )
        .await;
        assert_eq!(first, TokenRedeemResult::Ok);

        let second = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &token_nonce,
            &sealed_token,
            &[],
            RECIPIENT_A,
        )
        .await;
        assert_eq!(second, TokenRedeemResult::DoubleSpent);

        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .query_async(&mut conn)
            .await
            .expect("test cleanup must succeed");
    }

    /// One token + shared spend_id covers subsequent token-less wire envelopes
    /// **to the same recipient**.
    #[tokio::test]
    async fn spend_unit_covers_followup_chunks_without_new_token() {
        let token_issuer_key = random_bytes32();
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let (token_nonce, sealed_token) = issue_sealed(&token_issuer_key, &server_secret);
        let spend_id = random_bytes32();

        let Some(mut conn) = try_redis().await else {
            eprintln!("skipping spend-unit test: redis unavailable");
            return;
        };

        let spent_key = format!("spent:{}", hex::encode(Sha256::digest(token_nonce)));
        let unit = unit_key(&spend_id, RECIPIENT_A);
        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .arg(&unit)
            .query_async(&mut conn)
            .await
            .expect("cleanup");

        // First wire envelope pays with a token.
        let first = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &token_nonce,
            &sealed_token,
            &spend_id,
            RECIPIENT_A,
        )
        .await;
        assert_eq!(first, TokenRedeemResult::Ok);

        // Chunks 2..N: no token, same spend_id + recipient → covered.
        for _ in 0..5 {
            let follow = redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &[],
                &[],
                &spend_id,
                RECIPIENT_A,
            )
            .await;
            assert_eq!(follow, TokenRedeemResult::UnitCovered);
        }

        // Follow-up without spend_id still requires a token.
        let no_unit = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &[],
            &[],
            &[],
            RECIPIENT_A,
        )
        .await;
        assert_eq!(no_unit, TokenRedeemResult::MissingToken);

        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .arg(&unit)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    }

    /// The fix: spend_id paid for recipient A does not cover recipient B.
    #[tokio::test]
    async fn spend_unit_does_not_cover_different_recipient() {
        let token_issuer_key = random_bytes32();
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let (token_nonce, sealed_token) = issue_sealed(&token_issuer_key, &server_secret);
        let spend_id = random_bytes32();

        let Some(mut conn) = try_redis().await else {
            eprintln!("skipping recipient-binding test: redis unavailable");
            return;
        };

        let spent_key = format!("spent:{}", hex::encode(Sha256::digest(token_nonce)));
        let unit_a = unit_key(&spend_id, RECIPIENT_A);
        let unit_b = unit_key(&spend_id, RECIPIENT_B);
        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .arg(&unit_a)
            .arg(&unit_b)
            .query_async(&mut conn)
            .await
            .expect("cleanup");

        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &token_nonce,
                &sealed_token,
                &spend_id,
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::Ok
        );

        // Same spend_id, different recipient, no token → MissingToken (unit not paid for B).
        let cross = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &[],
            &[],
            &spend_id,
            RECIPIENT_B,
        )
        .await;
        assert_eq!(cross, TokenRedeemResult::MissingToken);

        // B can still open its own unit with its own token.
        let (nonce_b, sealed_b) = issue_sealed(&token_issuer_key, &server_secret);
        let spent_b = format!("spent:{}", hex::encode(Sha256::digest(nonce_b)));
        let _: () = redis::cmd("DEL")
            .arg(&spent_b)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &nonce_b,
                &sealed_b,
                &spend_id,
                RECIPIENT_B,
            )
            .await,
            TokenRedeemResult::Ok
        );
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &[],
                &[],
                &spend_id,
                RECIPIENT_B,
            )
            .await,
            TokenRedeemResult::UnitCovered
        );

        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .arg(&spent_b)
            .arg(&unit_a)
            .arg(&unit_b)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    }

    /// Cap holds per (spend_id, recipient); envelope 257 → UnitExhausted.
    #[tokio::test]
    async fn spend_unit_exhausted_at_max_envelopes() {
        let token_issuer_key = random_bytes32();
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let (token_nonce, sealed_token) = issue_sealed(&token_issuer_key, &server_secret);
        let spend_id = random_bytes32();

        let Some(mut conn) = try_redis().await else {
            eprintln!("skipping spend-unit exhaust test: redis unavailable");
            return;
        };

        let spent_key = format!("spent:{}", hex::encode(Sha256::digest(token_nonce)));
        let unit = unit_key(&spend_id, RECIPIENT_A);
        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .arg(&unit)
            .query_async(&mut conn)
            .await
            .expect("cleanup");

        // Seed unit at max-1 via first redeem, then force count to MAX.
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &token_nonce,
                &sealed_token,
                &spend_id,
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::Ok
        );
        let _: () = redis::cmd("SET")
            .arg(&unit)
            .arg(MAX_ENVELOPES_PER_SPEND_UNIT)
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .expect("seed max");

        let exhausted = redeem_token_checked(
            &mut conn,
            Some(&token_issuer_key),
            Some(&server_secret),
            &[],
            &[],
            &spend_id,
            RECIPIENT_A,
        )
        .await;
        assert_eq!(exhausted, TokenRedeemResult::UnitExhausted);

        let _: () = redis::cmd("DEL")
            .arg(&spent_key)
            .arg(&unit)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    }

    /// Cap is not shared across recipients: 256 to A then 256 to B each need
    /// their own paying first envelope and succeed independently.
    #[tokio::test]
    async fn spend_unit_caps_are_independent_per_recipient() {
        let token_issuer_key = random_bytes32();
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let spend_id = random_bytes32();
        let (nonce_a, sealed_a) = issue_sealed(&token_issuer_key, &server_secret);
        let (nonce_b, sealed_b) = issue_sealed(&token_issuer_key, &server_secret);

        let Some(mut conn) = try_redis().await else {
            eprintln!("skipping independent-cap test: redis unavailable");
            return;
        };

        let spent_a = format!("spent:{}", hex::encode(Sha256::digest(nonce_a)));
        let spent_b = format!("spent:{}", hex::encode(Sha256::digest(nonce_b)));
        let unit_a = unit_key(&spend_id, RECIPIENT_A);
        let unit_b = unit_key(&spend_id, RECIPIENT_B);
        let _: () = redis::cmd("DEL")
            .arg(&spent_a)
            .arg(&spent_b)
            .arg(&unit_a)
            .arg(&unit_b)
            .query_async(&mut conn)
            .await
            .expect("cleanup");

        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &nonce_a,
                &sealed_a,
                &spend_id,
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::Ok
        );
        // Force A to the cap.
        let _: () = redis::cmd("SET")
            .arg(&unit_a)
            .arg(MAX_ENVELOPES_PER_SPEND_UNIT)
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .expect("seed max A");
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &[],
                &[],
                &spend_id,
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::UnitExhausted
        );

        // B is a separate unit: paying envelope + follow-up still works.
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &nonce_b,
                &sealed_b,
                &spend_id,
                RECIPIENT_B,
            )
            .await,
            TokenRedeemResult::Ok
        );
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &[],
                &[],
                &spend_id,
                RECIPIENT_B,
            )
            .await,
            TokenRedeemResult::UnitCovered
        );

        let _: () = redis::cmd("DEL")
            .arg(&spent_a)
            .arg(&spent_b)
            .arg(&unit_a)
            .arg(&unit_b)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    }

    /// Empty spend_id: legacy per-envelope redemption (no unit bookkeeping).
    #[tokio::test]
    async fn empty_spend_id_is_per_envelope() {
        let token_issuer_key = random_bytes32();
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let (nonce1, sealed1) = issue_sealed(&token_issuer_key, &server_secret);
        let (nonce2, sealed2) = issue_sealed(&token_issuer_key, &server_secret);

        let Some(mut conn) = try_redis().await else {
            eprintln!("skipping empty-spend_id test: redis unavailable");
            return;
        };

        let spent1 = format!("spent:{}", hex::encode(Sha256::digest(nonce1)));
        let spent2 = format!("spent:{}", hex::encode(Sha256::digest(nonce2)));
        let _: () = redis::cmd("DEL")
            .arg(&spent1)
            .arg(&spent2)
            .query_async(&mut conn)
            .await
            .expect("cleanup");

        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &nonce1,
                &sealed1,
                &[],
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::Ok
        );
        // Second envelope without spend_id and without a token → missing.
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &[],
                &[],
                &[],
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::MissingToken
        );
        // Second envelope with its own token still works.
        assert_eq!(
            redeem_token_checked(
                &mut conn,
                Some(&token_issuer_key),
                Some(&server_secret),
                &nonce2,
                &sealed2,
                &[],
                RECIPIENT_A,
            )
            .await,
            TokenRedeemResult::Ok
        );

        let _: () = redis::cmd("DEL")
            .arg(&spent1)
            .arg(&spent2)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    }
}
