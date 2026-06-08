// ============================================================================
// Hybrid Post-Quantum Cryptography Implementation
// ============================================================================
//
// Implements hybrid (Ed25519 + ML-DSA-65) signature operations.
//
// Security: MIN(Ed25519, ML-DSA-65) — both must be broken to forge a signature.
// Ed25519 provides backward compatibility; ML-DSA-65 provides post-quantum
// security against "harvest now, decrypt later" attacks on identity keys.
//
// Key sizes (NIST FIPS 204 for ML-DSA-65):
// - ML-DSA-65 public key:  1952 bytes
// - ML-DSA-65 signing seed: 32 bytes (expanded 4032-byte key re-derived on sign)
// - ML-DSA-65 signature:   3309 bytes (detached)
// - Hybrid public key:     32 + 1952 = 1984 bytes
// - Hybrid private key:    32 + 32 + 1952 = 2016 bytes (with embedded pk)
// - Hybrid signature:      64 + 3309 = 3373 bytes
// ============================================================================

use super::types::key_sizes;
use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, B32,
};
// Trait methods only — aliased `as _` so they don't clash with the
// ed25519-dalek Signer/Verifier/Keypair names imported above.
use ml_dsa::{Keypair as _, Signer as _, Verifier as _};
use rand_core::{OsRng, RngCore};

// ── Size constants (re-exported for convenience) ──────────────────────────────

/// Ed25519 public key size
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 secret key seed size
pub const ED25519_SECRET_KEY_SIZE: usize = 32;
/// Ed25519 signature size
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// ML-DSA-65 public key size (FIPS 204)
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = key_sizes::ML_DSA_65_PUBLIC_KEY; // 1952
/// ML-DSA-65 stored secret size — the 32-byte signing seed
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = key_sizes::ML_DSA_65_SECRET_KEY; // 32
/// ML-DSA-65 detached signature size
pub const ML_DSA_65_SIGNATURE_SIZE: usize = key_sizes::ML_DSA_65_SIGNATURE; // 3309
/// Hybrid signature public key = Ed25519 (32) + ML-DSA-65 (1952)
pub const HYBRID_SIG_PUBLIC_KEY_SIZE: usize = key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY; // 1984
/// Hybrid private key = Ed25519 seed (32) + ML-DSA-65 seed (32) + ML-DSA-65 pk (1952)
pub const HYBRID_SIG_SECRET_KEY_SIZE: usize = key_sizes::HYBRID_SIG_SECRET_KEY; // 2016
/// Hybrid signature = Ed25519 sig (64) + ML-DSA-65 sig (3309)
pub const HYBRID_SIGNATURE_SIZE: usize = key_sizes::HYBRID_SIGNATURE; // 3373

// ── Prologue-based signing (for Kyber key signatures) ─────────────────────────

/// Build the sign message with prologue for any Kyber key.
///
/// Message = `"KonstruktX3DH-v1" || [0x00, suite_id] || public_key`
///
/// `suite_id`: 0x01 = ClassicX25519, 0x10 = HybridKyber1024X25519
pub fn build_prekey_sign_message(suite_id: u8, public_key: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(18 + public_key.len());
    message.extend_from_slice(b"KonstruktX3DH-v1");
    message.extend_from_slice(&[0x00, suite_id]);
    message.extend_from_slice(public_key);
    message
}

/// Verify an Ed25519 signature over a Kyber public key.
///
/// This is the Phase 1 approach: Ed25519 identity signs the ML-KEM public key.
pub fn verify_kyber_key_signature(
    verifying_key_bytes: &[u8],
    suite_id: u8,
    public_key: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let vk_array: [u8; 32] = verifying_key_bytes.try_into().context(format!(
        "verifying_key must be {} bytes",
        ED25519_PUBLIC_KEY_SIZE
    ))?;
    let vk = VerifyingKey::from_bytes(&vk_array)
        .map_err(|e| anyhow::anyhow!("Invalid verifying key: {}", e))?;

    let sig_array: [u8; 64] = signature_bytes.try_into().context(format!(
        "signature must be {} bytes",
        ED25519_SIGNATURE_SIZE
    ))?;
    let sig = Signature::from_bytes(&sig_array);

    let message = build_prekey_sign_message(suite_id, public_key);

    vk.verify(&message, &sig)
        .map_err(|_| anyhow::anyhow!("Kyber key signature verification failed"))
}

// ── Hybrid signature (Ed25519 + ML-DSA-65) ────────────────────────────────────

/// Split a hybrid public key into Ed25519 and ML-DSA-65 components.
fn split_hybrid_public_key(
    hybrid_pk: &[u8],
) -> Result<(
    &[u8; ED25519_PUBLIC_KEY_SIZE],
    &[u8; ML_DSA_65_PUBLIC_KEY_SIZE],
)> {
    if hybrid_pk.len() != HYBRID_SIG_PUBLIC_KEY_SIZE {
        anyhow::bail!(
            "Hybrid public key size mismatch: expected {}, got {}",
            HYBRID_SIG_PUBLIC_KEY_SIZE,
            hybrid_pk.len()
        );
    }
    let ed25519_pk: &[u8; ED25519_PUBLIC_KEY_SIZE] = hybrid_pk[..ED25519_PUBLIC_KEY_SIZE]
        .try_into()
        .context("Failed to extract Ed25519 public key from hybrid key")?;
    let mldsa_pk: &[u8; ML_DSA_65_PUBLIC_KEY_SIZE] = hybrid_pk[ED25519_PUBLIC_KEY_SIZE..]
        .try_into()
        .context("Failed to extract ML-DSA-65 public key from hybrid key")?;
    Ok((ed25519_pk, mldsa_pk))
}

/// Split a hybrid signature into Ed25519 and ML-DSA-65 components.
fn split_hybrid_signature(
    hybrid_sig: &[u8],
) -> Result<(
    &[u8; ED25519_SIGNATURE_SIZE],
    &[u8; ML_DSA_65_SIGNATURE_SIZE],
)> {
    if hybrid_sig.len() != HYBRID_SIGNATURE_SIZE {
        anyhow::bail!(
            "Hybrid signature size mismatch: expected {}, got {}",
            HYBRID_SIGNATURE_SIZE,
            hybrid_sig.len()
        );
    }
    let ed25519_sig: &[u8; ED25519_SIGNATURE_SIZE] = hybrid_sig[..ED25519_SIGNATURE_SIZE]
        .try_into()
        .context("Failed to extract Ed25519 signature from hybrid signature")?;
    let mldsa_sig: &[u8; ML_DSA_65_SIGNATURE_SIZE] = hybrid_sig[ED25519_SIGNATURE_SIZE..]
        .try_into()
        .context("Failed to extract ML-DSA-65 signature from hybrid signature")?;
    Ok((ed25519_sig, mldsa_sig))
}

/// Verify a hybrid (Ed25519 + ML-DSA-65) signature over arbitrary data.
///
/// Both signatures must be valid for the verification to succeed.
///
/// The hybrid public key format: [ed25519_pk (32)] [mldsa65_pk (1952)]
/// The hybrid signature format: [ed25519_sig (64)] [mldsa65_sig (3309)]
pub fn verify_hybrid_signature(
    hybrid_public_key: &[u8],
    message: &[u8],
    hybrid_signature: &[u8],
) -> Result<()> {
    let (ed25519_pk_bytes, mldsa_pk_bytes) = split_hybrid_public_key(hybrid_public_key)?;
    let (ed25519_sig_bytes, mldsa_sig_bytes) = split_hybrid_signature(hybrid_signature)?;

    // Verify Ed25519
    let ed25519_vk = VerifyingKey::from_bytes(ed25519_pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 verifying key in hybrid key: {}", e))?;
    let ed25519_sig = Signature::from_bytes(ed25519_sig_bytes);
    ed25519_vk
        .verify(message, &ed25519_sig)
        .map_err(|e| anyhow::anyhow!("Hybrid signature: Ed25519 verification failed: {}", e))?;

    // Verify ML-DSA-65
    let mldsa_pk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(&mldsa_pk_bytes[..])
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 public key size in hybrid key"))?;
    let mldsa_pk = MlDsaVerifyingKey::<MlDsa65>::decode(&mldsa_pk_enc);
    let mldsa_sig_enc = EncodedSignature::<MlDsa65>::try_from(&mldsa_sig_bytes[..])
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 signature size in hybrid signature"))?;
    let mldsa_sig = MlDsaSignature::<MlDsa65>::decode(&mldsa_sig_enc).ok_or_else(|| {
        anyhow::anyhow!("Invalid ML-DSA-65 signature encoding in hybrid signature")
    })?;
    mldsa_pk
        .verify(message, &mldsa_sig)
        .map_err(|e| anyhow::anyhow!("Hybrid signature: ML-DSA-65 verification failed: {}", e))?;

    Ok(())
}

/// Verify a hybrid signature over a Kyber public key.
///
/// Combines `build_prekey_sign_message` with `verify_hybrid_signature`.
pub fn verify_hybrid_kyber_key_signature(
    hybrid_verifying_key: &[u8],
    suite_id: u8,
    kyber_public_key: &[u8],
    hybrid_signature: &[u8],
) -> Result<()> {
    let message = build_prekey_sign_message(suite_id, kyber_public_key);
    verify_hybrid_signature(hybrid_verifying_key, &message, hybrid_signature)
}

// ── Key generation and signing (for tests / admin tools) ──────────────────────

/// Generate a hybrid (Ed25519 + ML-DSA-65) signature keypair.
///
/// Returns (private_key, public_key) as raw bytes.
/// Private key format: [ed25519_seed (32)] [mldsa65_seed (32)] [mldsa65_pk (1952)]
/// Public key format: [ed25519_pk (32)] [mldsa65_pk (1952)]
pub fn generate_hybrid_signature_keypair() -> (Vec<u8>, Vec<u8>) {
    // Ed25519
    let ed25519_sk = SigningKey::generate(&mut OsRng);
    let ed25519_pk = ed25519_sk.verifying_key();

    // ML-DSA-65 — store the 32-byte signing seed (the expanded 4032-byte key is
    // re-derived on demand at sign time). ml-dsa deprecated expanded import/export
    // in favour of seed storage. The embedded public key (1952) is kept for
    // convenience. pk and signature wire formats remain FIPS 204 standard.
    let mut rng = OsRng;
    let mut mldsa_seed = [0u8; 32];
    rng.fill_bytes(&mut mldsa_seed);
    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(mldsa_seed));
    let mldsa_pk_enc = mldsa_sk.verifying_key().encode(); // 1952 bytes

    // Private key: [ed25519_seed (32)] [mldsa65_seed (32)] [mldsa65_pk (1952)]
    let mut hybrid_sk = Vec::with_capacity(HYBRID_SIG_SECRET_KEY_SIZE);
    hybrid_sk.extend_from_slice(&ed25519_sk.to_bytes());
    hybrid_sk.extend_from_slice(&mldsa_seed);
    hybrid_sk.extend_from_slice(mldsa_pk_enc.as_slice());

    // Public key: [ed25519_pk (32)] [mldsa65_pk (1952)]
    let mut hybrid_pk = Vec::with_capacity(HYBRID_SIG_PUBLIC_KEY_SIZE);
    hybrid_pk.extend_from_slice(&ed25519_pk.to_bytes());
    hybrid_pk.extend_from_slice(mldsa_pk_enc.as_slice());

    (hybrid_sk, hybrid_pk)
}

/// Sign data with a hybrid private key.
/// Returns hybrid signature: [ed25519_sig (64)] [mldsa65_sig (3309)]
pub fn hybrid_sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != HYBRID_SIG_SECRET_KEY_SIZE {
        anyhow::bail!(
            "Hybrid private key size mismatch: expected {}, got {}",
            HYBRID_SIG_SECRET_KEY_SIZE,
            private_key.len()
        );
    }

    let ed25519_seed: &[u8; 32] = private_key[..32].try_into().unwrap();
    let mldsa_seed_bytes = &private_key[32..32 + ML_DSA_65_SECRET_KEY_SIZE];

    // Ed25519 signature
    let ed25519_sk = SigningKey::from_bytes(ed25519_seed);
    let ed25519_sig = ed25519_sk.sign(message);

    // ML-DSA-65 signature — re-derive the signing key from its 32-byte seed.
    let mldsa_seed: [u8; 32] = mldsa_seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-DSA-65 seed size error"))?;
    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(mldsa_seed));
    let mldsa_sig = mldsa_sk
        .try_sign(message)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {}", e))?;

    // Concatenate
    let mut hybrid_sig = Vec::with_capacity(HYBRID_SIGNATURE_SIZE);
    hybrid_sig.extend_from_slice(&ed25519_sig.to_bytes());
    hybrid_sig.extend_from_slice(mldsa_sig.encode().as_slice());

    Ok(hybrid_sig)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_kyber_key_signature_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let kyber_pk = vec![0x42u8; 1184];

        let message = build_prekey_sign_message(0x10, &kyber_pk);
        let sig = sk.sign(&message);

        let result = verify_kyber_key_signature(&vk.to_bytes(), 0x10, &kyber_pk, &sig.to_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_kyber_key_signature_wrong_key() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let kyber_pk = vec![0x42u8; 1184];

        let message = build_prekey_sign_message(0x10, &kyber_pk);
        let sig = sk_a.sign(&message);

        let result = verify_kyber_key_signature(
            &sk_b.verifying_key().to_bytes(),
            0x10,
            &kyber_pk,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let (sk, pk) = generate_hybrid_signature_keypair();
        let message = b"Test hybrid signature";

        let sig = hybrid_sign(&sk, message).unwrap();
        assert_eq!(sig.len(), HYBRID_SIGNATURE_SIZE);

        let result = verify_hybrid_signature(&pk, message, &sig);
        assert!(
            result.is_ok(),
            "Hybrid verification should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_hybrid_verify_rejects_tampered_message() {
        let (sk, pk) = generate_hybrid_signature_keypair();
        let message = b"Original";
        let tampered = b"Tampered!";

        let sig = hybrid_sign(&sk, message).unwrap();
        let result = verify_hybrid_signature(&pk, tampered, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_verify_rejects_tampered_ed25519_portion() {
        let (sk, pk) = generate_hybrid_signature_keypair();
        let message = b"Test";

        let mut sig = hybrid_sign(&sk, message).unwrap();
        sig[0] ^= 0xFF;

        let result = verify_hybrid_signature(&pk, message, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_verify_rejects_tampered_mldsa_portion() {
        let (sk, pk) = generate_hybrid_signature_keypair();
        let message = b"Test";

        let mut sig = hybrid_sign(&sk, message).unwrap();
        sig[ED25519_SIGNATURE_SIZE] ^= 0xFF;

        let result = verify_hybrid_signature(&pk, message, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_verify_rejects_wrong_key() {
        let (sk_a, _) = generate_hybrid_signature_keypair();
        let (_, pk_b) = generate_hybrid_signature_keypair();
        let message = b"Test";

        let sig = hybrid_sign(&sk_a, message).unwrap();
        let result = verify_hybrid_signature(&pk_b, message, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hybrid_kyber_key_signature_roundtrip() {
        let (sk, pk) = generate_hybrid_signature_keypair();
        let kyber_pk = vec![0x55u8; 1184];

        let message = build_prekey_sign_message(0x10, &kyber_pk);
        let sig = hybrid_sign(&sk, &message).unwrap();

        let result = verify_hybrid_kyber_key_signature(&pk, 0x10, &kyber_pk, &sig);
        assert!(
            result.is_ok(),
            "Hybrid Kyber key verification should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_constants_consistency() {
        assert_eq!(ML_DSA_65_PUBLIC_KEY_SIZE, key_sizes::ML_DSA_65_PUBLIC_KEY);
        assert_eq!(ML_DSA_65_SIGNATURE_SIZE, key_sizes::ML_DSA_65_SIGNATURE);
        assert_eq!(
            HYBRID_SIG_PUBLIC_KEY_SIZE,
            key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY
        );
        assert_eq!(HYBRID_SIGNATURE_SIZE, key_sizes::HYBRID_SIGNATURE);
    }
}
