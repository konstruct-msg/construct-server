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
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
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
/// Returns `None` if `seed_b64` is not valid base64.
pub fn derive_token_enc_static_secret(seed_b64: &str) -> Option<X25519StaticSecret> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let seed_bytes = STANDARD.decode(seed_b64.trim()).ok()?;
    let hk = Hkdf::<Sha256>::new(None, &seed_bytes);
    let mut x25519_seed = [0u8; 32];
    hk.expand(TOKEN_ENC_INFO, &mut x25519_seed).ok()?;
    Some(X25519StaticSecret::from(x25519_seed))
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
pub fn verify_token(token: &[u8; 32], nonce: &[u8; 32], k_scalar_bytes: &[u8; 32]) -> bool {
    let k = match Option::<Scalar>::from(Scalar::from_canonical_bytes(*k_scalar_bytes)) {
        Some(k) => k,
        None => return false,
    };

    let t = hash_to_ristretto(nonce);
    let n = k * t;
    let expected = derive_token(&n.compress().to_bytes(), nonce);

    expected.ct_eq(token).into()
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
        let seed_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            random_bytes32(),
        );
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
}
