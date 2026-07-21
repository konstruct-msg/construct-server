//! ConstructPrivacyPass server-side primitives — VOPRF (Ristretto255) token
//! redemption and X25519 sealed-box opening for stealth-sender anti-abuse.
//!
//! The VOPRF math here (`hash_to_ristretto`, `derive_token`, `verify_token`) is a
//! byte-for-byte port of the client/core implementation in
//! `construct-core/src/crypto/privacy_pass/mod.rs` — construct-server does not
//! depend on construct-core, so this crate keeps its own copy. Keep the two in
//! sync: same `curve25519-dalek` major version, same HKDF info strings, or
//! client-issued tokens will stop verifying server-side.
//!
//! Scheme: OPRF(ristretto255, SHA-512), documented in full in construct-core.
//!
//! The sealed-box format for `SealedInner.token_bytes` is documented (with the
//! matching decrypt pseudocode) in
//! `ConstructMessenger/Networking/gRPC/Services/ServerKeyManager.swift`:
//! `ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const TOKEN_ENC_INFO: &[u8] = b"construct-token-enc-v1";
const TOKEN_SEAL_INFO: &[u8] = b"construct-token-seal-v1";
const PP_HKDF_INFO: &[u8] = b"ConstructPP-v1";

/// Errors from Privacy Pass server-side operations.
#[derive(Debug)]
pub enum PrivacyPassError {
    /// `token_bytes` was shorter than the minimum sealed-box size.
    SealedBoxTooShort,
    /// AEAD decryption failed (wrong key, corrupted ciphertext, or tampering).
    DecryptFailed,
    /// Ephemeral public key in the sealed box was not a valid Curve25519 point.
    InvalidEphemeralKey,
}

impl std::fmt::Display for PrivacyPassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SealedBoxTooShort => write!(f, "sealed token_bytes too short"),
            Self::DecryptFailed => write!(f, "sealed token_bytes decryption failed"),
            Self::InvalidEphemeralKey => write!(f, "sealed token_bytes: invalid ephemeral key"),
        }
    }
}

impl std::error::Error for PrivacyPassError {}

// ──────────────────────────────────────────────────────────────────────────
// Token-encryption key derivation (shared with identity-service)
// ──────────────────────────────────────────────────────────────────────────

/// Derive the server's X25519 token-encryption static secret from the federation
/// signing key seed (base64). Same derivation identity-service uses to publish
/// the public half at `/.well-known/construct-server` as `token_encryption_key`.
///
/// Returns `None` if `seed_b64` is not valid base64 or does not decode to exactly
/// 32 bytes (matches the federation signer's invariant).
pub fn derive_token_enc_static_secret(seed_b64: &str) -> Option<X25519StaticSecret> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let seed_bytes = STANDARD.decode(seed_b64.trim()).ok()?;
    // Require a full 32-byte seed. HKDF will happily expand an empty or short IKM into
    // a deterministic *wrong* key, which silently masks an unset SERVER_SIGNING_KEY (an
    // empty `${VAR}` interpolation) as a "working" token_encryption_key — callers then
    // publish a bogus key instead of logging "unavailable". Fail loud instead.
    if seed_bytes.len() != 32 {
        return None;
    }
    let hk = Hkdf::<Sha256>::new(None, &seed_bytes);
    let mut x25519_seed = [0u8; 32];
    hk.expand(TOKEN_ENC_INFO, &mut x25519_seed).ok()?;
    Some(X25519StaticSecret::from(x25519_seed))
}

/// Derive the base64-encoded X25519 public key used to encrypt Privacy Pass tokens
/// in `SealedInner`. This is the value published at `/.well-known/construct-server`
/// as `token_encryption_key`.
///
/// Returns `None` if `seed_b64` is not valid base64.
pub fn derive_token_enc_public_key_base64(seed_b64: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let static_secret = derive_token_enc_static_secret(seed_b64)?;
    let public_key = X25519PublicKey::from(&static_secret);
    Some(STANDARD.encode(public_key.as_bytes()))
}

// ──────────────────────────────────────────────────────────────────────────
// Sealed-box opening (X25519 + HKDF-SHA256 + ChaChaPoly)
// ──────────────────────────────────────────────────────────────────────────

/// Open a `token_bytes` sealed box produced by the client's `ServerKeyManager.sealBox`.
///
/// Expects `ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`.
pub fn open_sealed_token_bytes(
    sealed: &[u8],
    server_secret: &X25519StaticSecret,
) -> Result<Vec<u8>, PrivacyPassError> {
    const EPH_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    if sealed.len() < EPH_LEN + NONCE_LEN + TAG_LEN {
        return Err(PrivacyPassError::SealedBoxTooShort);
    }

    let ephemeral_pub_bytes: [u8; 32] = sealed[..EPH_LEN]
        .try_into()
        .map_err(|_| PrivacyPassError::InvalidEphemeralKey)?;
    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);

    let nonce_bytes = &sealed[EPH_LEN..EPH_LEN + NONCE_LEN];
    let ciphertext_and_tag = &sealed[EPH_LEN + NONCE_LEN..];

    let shared_secret = server_secret.diffie_hellman(&ephemeral_pub);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(TOKEN_SEAL_INFO, &mut sym_key)
        .map_err(|_| PrivacyPassError::DecryptFailed)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| PrivacyPassError::DecryptFailed)
}

// ──────────────────────────────────────────────────────────────────────────
// VOPRF redemption (ported from construct-core/src/crypto/privacy_pass/mod.rs)
// ──────────────────────────────────────────────────────────────────────────

/// Map arbitrary bytes to a Ristretto255 point using hash-to-group (Elligator2
/// via `RistrettoPoint::from_hash`). Must match construct-core exactly.
///
/// Uses `sha2-dalek-compat` (sha2 pinned to 0.10, renamed) because
/// `RistrettoPoint::from_hash` requires `digest` 0.10's `Digest` trait, which the
/// sha2 0.11 used elsewhere in this crate no longer implements.
fn hash_to_ristretto(data: &[u8]) -> RistrettoPoint {
    use sha2_dalek_compat::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(data);
    RistrettoPoint::from_hash(h)
}

/// `HKDF-SHA512(n_compressed ‖ nonce, info="ConstructPP-v1")` truncated to 32 bytes.
fn derive_token(n_compressed: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let ikm: Vec<u8> = n_compressed.iter().chain(nonce.iter()).copied().collect();
    let hk = Hkdf::<sha2::Sha512>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(PP_HKDF_INFO, &mut out)
        .expect("HKDF-SHA512 with 32-byte output always succeeds");
    out
}

/// Redemption-time verification: re-derive the expected token from `(nonce, k)`
/// and compare against the client-presented `token` in constant time.
///
/// `k_scalar_bytes` is the server's Privacy Pass issuer scalar (`TOKEN_ISSUER_KEY`).
/// Interpreted with `from_bytes_mod_order` to match identity-service's `IssueTokens` —
/// a non-canonical key encoding must map to the same scalar on both sides, otherwise
/// every token issues fine but fails redemption.
pub fn verify_token(token: &[u8; 32], nonce: &[u8; 32], k_scalar_bytes: &[u8; 32]) -> bool {
    let k = Scalar::from_bytes_mod_order(*k_scalar_bytes);

    let t = hash_to_ristretto(nonce);
    let n = k * t;
    let expected = derive_token(&n.compress().to_bytes(), nonce);

    expected.ct_eq(token).into()
}

// ──────────────────────────────────────────────────────────────────────────
// Verifiable VOPRF — batched DLEQ (Phase C)
//
// Proves the issuer evaluated every blinded point with the SAME, publicly-committed scalar `k`
// (`K = k·G`) — closing the malicious-issuer key-tagging channel (a per-user `k_u` de-anonymises a
// sealed sender despite blinding). Non-interactive batched Chaum-Pedersen with a deterministic
// (RFC-6979-style) nonce. The transcript below is a CLIENT-PARITY CONTRACT: iOS/Android reimplement
// verification byte-for-byte, so any change here is a wire break — see
// construct-docs/cryptocore/privacy-pass-dleq-v1.md.
// ──────────────────────────────────────────────────────────────────────────

const DLEQ_DOMAIN: &[u8] = b"ConstructPP-DLEQ-v1";

/// SHA-512 wide-reduction of an ordered list of byte-slices to a Ristretto scalar (same
/// `sha2_dalek_compat` path as `hash_to_ristretto`, so issuance and client verification reduce
/// identically). Callers prepend `DLEQ_DOMAIN` + a 1-byte context tag.
fn dleq_hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    use sha2_dalek_compat::{Digest, Sha512};
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    Scalar::from_hash(h)
}

/// Decompress a 32-byte compressed Ristretto point, rejecting the identity.
fn decompress_nonidentity(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    let p = CompressedRistretto::from_slice(bytes).ok()?.decompress()?;
    if p.is_identity() {
        return None;
    }
    Some(p)
}

/// The issuer's public commitment `K = k·G` (compressed Ristretto, 32 bytes) — published in
/// well-known as `token_issuer_public` and pinned by clients. `k` is `TOKEN_ISSUER_KEY`, reduced
/// with `from_bytes_mod_order` to match issuance/redemption.
pub fn issuer_public_key(k_scalar_bytes: &[u8; 32]) -> [u8; 32] {
    let k = Scalar::from_bytes_mod_order(*k_scalar_bytes);
    (RISTRETTO_BASEPOINT_POINT * k).compress().to_bytes()
}

/// Deterministic random-linear-combination of the `(B_i, Z_i)` batch — identical on prover and
/// verifier. Returns `None` if empty, length-mismatched, or any point fails to decompress / is the
/// identity. `k_pub` is the committed `K` (bound into the seed so a proof can't be replayed under a
/// different commitment).
fn compute_composites(
    k_pub: &[u8; 32],
    blinded: &[[u8; 32]],
    evaluated: &[[u8; 32]],
) -> Option<(RistrettoPoint, RistrettoPoint)> {
    use sha2_dalek_compat::{Digest, Sha512};

    if blinded.is_empty() || blinded.len() != evaluated.len() {
        return None;
    }

    let mut b_pts = Vec::with_capacity(blinded.len());
    let mut z_pts = Vec::with_capacity(evaluated.len());
    for (b, z) in blinded.iter().zip(evaluated.iter()) {
        b_pts.push(decompress_nonidentity(b)?);
        z_pts.push(decompress_nonidentity(z)?);
    }

    // seed = SHA512(DOMAIN ‖ 0x00 ‖ K ‖ Σ_i (B_i ‖ Z_i))
    let mut sh = Sha512::new();
    sh.update(DLEQ_DOMAIN);
    sh.update([0x00u8]);
    sh.update(k_pub);
    for (b, z) in blinded.iter().zip(evaluated.iter()) {
        sh.update(b);
        sh.update(z);
    }
    let seed = sh.finalize();

    // M = Σ d_i·B_i, Zc = Σ d_i·Z_i, d_i = H(DOMAIN ‖ 0x01 ‖ seed ‖ u32_be(i) ‖ B_i ‖ Z_i)
    let mut m = RistrettoPoint::identity();
    let mut zc = RistrettoPoint::identity();
    for (i, (b, z)) in blinded.iter().zip(evaluated.iter()).enumerate() {
        let idx = (i as u32).to_be_bytes();
        let d = dleq_hash_to_scalar(&[DLEQ_DOMAIN, &[0x01], &seed[..], &idx[..], &b[..], &z[..]]);
        m += d * b_pts[i];
        zc += d * z_pts[i];
    }
    Some((m, zc))
}

/// Generate a batched DLEQ proof that every `evaluated[i] == k·blinded[i]` under the same `k` whose
/// public commitment is `K = k·G`. Returns a 64-byte proof `challenge(32) ‖ response(32)`, or
/// `None` if the batch is empty/mismatched or any point is invalid.
pub fn generate_dleq_proof(
    k_scalar_bytes: &[u8; 32],
    blinded: &[[u8; 32]],
    evaluated: &[[u8; 32]],
) -> Option<[u8; 64]> {
    let k = Scalar::from_bytes_mod_order(*k_scalar_bytes);
    let k_pub = issuer_public_key(k_scalar_bytes);

    let (m, zc) = compute_composites(&k_pub, blinded, evaluated)?;
    let m_c = m.compress().to_bytes();
    let zc_c = zc.compress().to_bytes();

    // Deterministic nonce t = H(DOMAIN ‖ 0x02 ‖ k ‖ M ‖ Zc) — binds the secret (unpredictable) and
    // the statement (never repeats across distinct (M,Zc)); no RNG, so no reuse-leaks-k failure.
    let k_canon = k.to_bytes();
    let t = dleq_hash_to_scalar(&[DLEQ_DOMAIN, &[0x02], &k_canon[..], &m_c[..], &zc_c[..]]);

    let a1 = RISTRETTO_BASEPOINT_POINT * t;
    let a2 = m * t;
    let c = dleq_hash_to_scalar(&[
        DLEQ_DOMAIN,
        &[0x03],
        &k_pub[..],
        &m_c[..],
        &zc_c[..],
        &a1.compress().to_bytes()[..],
        &a2.compress().to_bytes()[..],
    ]);
    let s = t + c * k;

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&c.to_bytes());
    proof[32..].copy_from_slice(&s.to_bytes());
    Some(proof)
}

/// Verify a batched DLEQ proof against the pinned public commitment `issuer_public` (`K`). Accepts
/// iff the same `k` links `K = k·G` and every `evaluated[i] = k·blinded[i]`. A per-user `k_u`
/// (`K = k·G` but `Z = k_u·B`) is rejected — the exact key-tagging threat Phase C closes.
pub fn verify_dleq_proof(
    issuer_public: &[u8; 32],
    blinded: &[[u8; 32]],
    evaluated: &[[u8; 32]],
    proof: &[u8; 64],
) -> bool {
    let c_bytes: [u8; 32] = proof[..32].try_into().expect("32-byte slice");
    let s_bytes: [u8; 32] = proof[32..].try_into().expect("32-byte slice");
    let c = Option::<Scalar>::from(Scalar::from_canonical_bytes(c_bytes));
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes));
    let (c, s) = match (c, s) {
        (Some(c), Some(s)) => (c, s),
        _ => return false, // non-canonical scalar encoding
    };

    let k_point = match CompressedRistretto::from_slice(issuer_public)
        .ok()
        .and_then(|cp| cp.decompress())
    {
        Some(p) => p,
        None => return false,
    };

    let (m, zc) = match compute_composites(issuer_public, blinded, evaluated) {
        Some(v) => v,
        None => return false,
    };
    let m_c = m.compress().to_bytes();
    let zc_c = zc.compress().to_bytes();

    // A1' = s·G − c·K, A2' = s·M − c·Zc; accept iff H(...A1'‖A2') == c.
    let a1p = s * RISTRETTO_BASEPOINT_POINT - c * k_point;
    let a2p = s * m - c * zc;
    let c_prime = dleq_hash_to_scalar(&[
        DLEQ_DOMAIN,
        &[0x03],
        &issuer_public[..],
        &m_c[..],
        &zc_c[..],
        &a1p.compress().to_bytes()[..],
        &a2p.compress().to_bytes()[..],
    ]);

    c_prime.ct_eq(&c).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_bytes32() -> [u8; 32] {
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        b
    }

    /// Full client blind → server evaluate → client finalize → server verify
    /// round trip, self-contained (proves internal consistency of this crate's
    /// port — cross-implementation compatibility with construct-core is
    /// validated separately, see decision doc's Phase 1 risk note).
    #[test]
    fn voprf_round_trip() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let nonce = random_bytes32();

        // Client: blind
        let t = hash_to_ristretto(&nonce);
        let r = Scalar::from_bytes_mod_order(random_bytes32());
        let blinded = r * t;

        // Server: evaluate
        let z = k * blinded;

        // Client: finalize (unblind + derive token)
        let r_inv = r.invert();
        let n = r_inv * z;
        let token = derive_token(&n.compress().to_bytes(), &nonce);

        // Server: verify
        assert!(verify_token(&token, &nonce, &k.to_bytes()));
    }

    /// A non-canonical key encoding (≥ group order, e.g. raw random bytes with high
    /// bits set) must still round-trip: issuance (`from_bytes_mod_order` in
    /// identity-service) and redemption must reduce it to the same scalar.
    #[test]
    fn voprf_round_trip_with_non_canonical_key_bytes() {
        let k_bytes = [0xff_u8; 32]; // far above the ristretto255 group order
        let k = Scalar::from_bytes_mod_order(k_bytes);
        let nonce = random_bytes32();

        let t = hash_to_ristretto(&nonce);
        let r = Scalar::from_bytes_mod_order(random_bytes32());
        let blinded = r * t;
        let z = k * blinded;
        let n = r.invert() * z;
        let token = derive_token(&n.compress().to_bytes(), &nonce);

        assert!(verify_token(&token, &nonce, &k_bytes));
    }

    /// An empty or short seed must yield `None`, never a bogus key derived from a
    /// short HKDF IKM — otherwise an unset `SERVER_SIGNING_KEY` (empty `${VAR}`
    /// interpolation) silently masquerades as a working token_encryption_key.
    #[test]
    fn token_enc_derivation_rejects_empty_and_short_seed() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        assert!(derive_token_enc_static_secret("").is_none(), "empty seed");
        // 16 bytes base64-encoded — decodes fine but is too short.
        let short = STANDARD.encode([0u8; 16]);
        assert!(
            derive_token_enc_static_secret(&short).is_none(),
            "16-byte seed"
        );
        // Exactly 32 bytes derives a key.
        let ok = STANDARD.encode([7u8; 32]);
        assert!(
            derive_token_enc_static_secret(&ok).is_some(),
            "32-byte seed"
        );
    }

    #[test]
    fn voprf_wrong_key_fails() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let wrong_k = Scalar::from_bytes_mod_order(random_bytes32());
        let nonce = random_bytes32();

        let t = hash_to_ristretto(&nonce);
        let r = Scalar::from_bytes_mod_order(random_bytes32());
        let blinded = r * t;
        let z = k * blinded;
        let n = r.invert() * z;
        let token = derive_token(&n.compress().to_bytes(), &nonce);

        assert!(!verify_token(&token, &nonce, &wrong_k.to_bytes()));
    }

    #[test]
    fn voprf_tampered_nonce_fails() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let nonce = random_bytes32();
        let other_nonce = random_bytes32();

        let t = hash_to_ristretto(&nonce);
        let r = Scalar::from_bytes_mod_order(random_bytes32());
        let blinded = r * t;
        let z = k * blinded;
        let n = r.invert() * z;
        let token = derive_token(&n.compress().to_bytes(), &nonce);

        assert!(!verify_token(&token, &other_nonce, &k.to_bytes()));
    }

    #[test]
    fn sealed_box_round_trip() {
        let seed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, random_bytes32());
        let server_secret = derive_token_enc_static_secret(&seed_b64).unwrap();
        let server_pub = X25519PublicKey::from(&server_secret);

        // Emulate the client's sealBox(): ephemeral X25519 + HKDF-SHA256 + ChaChaPoly.
        let ephemeral_secret = X25519StaticSecret::from(random_bytes32());
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(&server_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(TOKEN_SEAL_INFO, &mut sym_key).unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
        let nonce_bytes = random_bytes32();
        let nonce = Nonce::from_slice(&nonce_bytes[..12]);
        let plaintext = b"a 32 byte finalized token value";
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

        let mut sealed = Vec::new();
        sealed.extend_from_slice(ephemeral_pub.as_bytes());
        sealed.extend_from_slice(&nonce_bytes[..12]);
        sealed.extend_from_slice(&ciphertext);

        let opened = open_sealed_token_bytes(&sealed, &server_secret).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn sealed_box_too_short_rejected() {
        let server_secret = X25519StaticSecret::from(random_bytes32());
        assert!(matches!(
            open_sealed_token_bytes(&[0u8; 10], &server_secret),
            Err(PrivacyPassError::SealedBoxTooShort)
        ));
    }

    #[test]
    fn sealed_box_wrong_key_fails() {
        let server_secret = X25519StaticSecret::from(random_bytes32());
        let other_secret = X25519StaticSecret::from(random_bytes32());
        let other_pub = X25519PublicKey::from(&other_secret);

        let ephemeral_secret = X25519StaticSecret::from(random_bytes32());
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
        // Seal to the WRONG recipient (other_pub, not server_secret's public half).
        let shared = ephemeral_secret.diffie_hellman(&other_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(TOKEN_SEAL_INFO, &mut sym_key).unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
        let nonce_bytes = random_bytes32();
        let nonce = Nonce::from_slice(&nonce_bytes[..12]);
        let ciphertext = cipher.encrypt(nonce, b"secret".as_slice()).unwrap();

        let mut sealed = Vec::new();
        sealed.extend_from_slice(ephemeral_pub.as_bytes());
        sealed.extend_from_slice(&nonce_bytes[..12]);
        sealed.extend_from_slice(&ciphertext);

        assert!(matches!(
            open_sealed_token_bytes(&sealed, &server_secret),
            Err(PrivacyPassError::DecryptFailed)
        ));
    }

    // ── Verifiable VOPRF / DLEQ (Phase C) ──────────────────────────────────

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Build a `(blinded, evaluated)` batch honestly evaluated under `k`
    /// (`B_i = r_i·H(nonce_i)`, `Z_i = k·B_i`).
    fn make_batch(k: &Scalar, n: usize) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut blinded = Vec::with_capacity(n);
        let mut evaluated = Vec::with_capacity(n);
        for _ in 0..n {
            let t = hash_to_ristretto(&random_bytes32());
            let r = Scalar::from_bytes_mod_order(random_bytes32());
            let b = r * t;
            let z = k * b;
            blinded.push(b.compress().to_bytes());
            evaluated.push(z.compress().to_bytes());
        }
        (blinded, evaluated)
    }

    #[test]
    fn dleq_round_trip_single_and_batch() {
        for n in [1usize, 20] {
            let k = Scalar::from_bytes_mod_order(random_bytes32());
            let k_bytes = k.to_bytes();
            let (blinded, evaluated) = make_batch(&k, n);
            let proof = generate_dleq_proof(&k_bytes, &blinded, &evaluated).expect("proof");
            let k_pub = issuer_public_key(&k_bytes);
            assert!(
                verify_dleq_proof(&k_pub, &blinded, &evaluated, &proof),
                "honest batch of {n} must verify"
            );
        }
    }

    /// The exact threat Phase C closes: evaluating under a per-user `k_u` while publishing `K = k·G`
    /// must NOT verify — neither with a proof forged under `k`, nor with an honest proof under `k_u`
    /// checked against the published `K`.
    #[test]
    fn dleq_per_user_key_rejected() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let k_u = Scalar::from_bytes_mod_order(random_bytes32());
        let (blinded, evaluated) = make_batch(&k_u, 5); // evaluated under k_u
        let k_pub = issuer_public_key(&k.to_bytes()); // committed to k

        let proof_under_k = generate_dleq_proof(&k.to_bytes(), &blinded, &evaluated).expect("proof");
        assert!(
            !verify_dleq_proof(&k_pub, &blinded, &evaluated, &proof_under_k),
            "k_u evaluation must fail against the committed K"
        );

        let proof_under_ku =
            generate_dleq_proof(&k_u.to_bytes(), &blinded, &evaluated).expect("proof");
        assert!(
            !verify_dleq_proof(&k_pub, &blinded, &evaluated, &proof_under_ku),
            "honest k_u proof must fail against the published K"
        );
        assert!(
            verify_dleq_proof(&issuer_public_key(&k_u.to_bytes()), &blinded, &evaluated, &proof_under_ku),
            "k_u proof verifies only against K_u (sanity)"
        );
    }

    #[test]
    fn dleq_tampered_z_rejected() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let k_bytes = k.to_bytes();
        let (blinded, mut evaluated) = make_batch(&k, 4);
        let proof = generate_dleq_proof(&k_bytes, &blinded, &evaluated).unwrap();
        let k_pub = issuer_public_key(&k_bytes);
        assert!(verify_dleq_proof(&k_pub, &blinded, &evaluated, &proof));

        // Replace one evaluated point with a different valid point.
        evaluated[2] = (k * hash_to_ristretto(&random_bytes32()))
            .compress()
            .to_bytes();
        assert!(!verify_dleq_proof(&k_pub, &blinded, &evaluated, &proof));
    }

    /// The proof binds the batch ORDER (seed + per-index `d_i`). A verifier that reorders the
    /// (still-valid) pairs must reject — clients verify in the same order they exchanged.
    #[test]
    fn dleq_reordered_batch_rejected() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let k_bytes = k.to_bytes();
        let (mut blinded, mut evaluated) = make_batch(&k, 3);
        let proof = generate_dleq_proof(&k_bytes, &blinded, &evaluated).unwrap();
        let k_pub = issuer_public_key(&k_bytes);
        blinded.swap(0, 2);
        evaluated.swap(0, 2);
        assert!(!verify_dleq_proof(&k_pub, &blinded, &evaluated, &proof));
    }

    #[test]
    fn dleq_malformed_proof_rejected() {
        let k = Scalar::from_bytes_mod_order(random_bytes32());
        let (blinded, evaluated) = make_batch(&k, 2);
        let k_pub = issuer_public_key(&k.to_bytes());
        // All-0xFF is a non-canonical scalar encoding for both halves → reject, never panic.
        assert!(!verify_dleq_proof(&k_pub, &blinded, &evaluated, &[0xffu8; 64]));
        // Empty / mismatched batches → reject.
        assert!(generate_dleq_proof(&k.to_bytes(), &[], &[]).is_none());
        assert!(generate_dleq_proof(&k.to_bytes(), &blinded, &evaluated[..1]).is_none());
    }

    /// Deterministic-nonce ⇒ the whole proof is a pure function of `(k, blinded, evaluated)`. Pins a
    /// golden 64-byte proof over fixed inputs so an iOS/Android reimplementation can cross-check the
    /// transcript byte-for-byte (client-parity contract). If this breaks, the wire format changed.
    #[test]
    fn dleq_kat_vector() {
        let k_bytes = [7u8; 32];
        let k = Scalar::from_bytes_mod_order(k_bytes);
        let mk = |label: &[u8]| -> [u8; 32] {
            let t = hash_to_ristretto(label);
            let r = Scalar::from_bytes_mod_order([3u8; 32]);
            (r * t).compress().to_bytes()
        };
        let blinded = vec![mk(b"kat-0"), mk(b"kat-1")];
        let evaluated: Vec<[u8; 32]> = blinded
            .iter()
            .map(|b| {
                let p = CompressedRistretto::from_slice(b).unwrap().decompress().unwrap();
                (k * p).compress().to_bytes()
            })
            .collect();

        let proof = generate_dleq_proof(&k_bytes, &blinded, &evaluated).unwrap();
        // Determinism: regenerating yields identical bytes.
        let proof2 = generate_dleq_proof(&k_bytes, &blinded, &evaluated).unwrap();
        assert_eq!(proof, proof2, "deterministic nonce ⇒ stable proof");
        // Self-consistency.
        assert!(verify_dleq_proof(&issuer_public_key(&k_bytes), &blinded, &evaluated, &proof));

        // Golden vector — the client-parity contract (privacy-pass-dleq-v1.md). A change here means
        // the DLEQ transcript changed and every client verifier must be updated in lockstep.
        const KAT_PROOF_HEX: &str = "a5fc43539f4acf319af0035bc73a19006588f75a5d425fc3039e906597c08d06bfa8b0cd50bb08d6d7bcb90dae2222fd2384e8404de57260fd412f729d29ab08";
        assert_eq!(hex_encode(&proof), KAT_PROOF_HEX, "DLEQ transcript changed — wire break");
    }
}
