// ============================================================================
// Post-Quantum Cryptography Validation
// ============================================================================
//
// Server-side validation utilities for hybrid post-quantum key bundles.
// The server validates format and key lengths, but does NOT perform
// cryptographic verification (that's the client's responsibility).
//
// ============================================================================

use super::types::key_sizes;
use crate::e2e::SuiteKeyMaterial;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
/// Validates key material for Post-Quantum Hybrid suite (suite_id = 2)
///
/// Validates:
/// - Identity key: Hybrid signature public key (Ed25519 + ML-DSA-65) = 1984 bytes
/// - Signed prekey: Hybrid KEM public key (X25519 + ML-KEM-768) = 1216 bytes
/// - One-time prekeys: Hybrid KEM public key (X25519 + ML-KEM-768) = 1216 bytes each
///
/// Note: This function is always available, but hybrid suite (suite_id=2) is only
/// accepted when post-quantum feature is enabled. When feature is disabled, the suite
/// will be rejected in ServerCryptoValidator before this function is called.
#[cfg(feature = "post-quantum")]
pub fn validate_hybrid_suite_key_material(suite: &SuiteKeyMaterial) -> Result<()> {
    // Validate identity key (hybrid signature public key)
    let identity_bytes = BASE64
        .decode(&suite.identity_key)
        .context("Invalid base64 in identity_key")?;

    // Identity key should be hybrid signature public key: Ed25519 (32) + ML-DSA-65 (1952) = 1984 bytes
    if identity_bytes.len() != key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY {
        return Err(anyhow::anyhow!(
            "Identity key must be {} bytes for hybrid suite (got {} bytes). \
             Expected: Ed25519 (32) + ML-DSA-65 (1952) = {} bytes",
            key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY,
            identity_bytes.len(),
            key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY
        ));
    }

    // Validate signed prekey (hybrid KEM public key)
    let prekey_bytes = BASE64
        .decode(&suite.signed_prekey)
        .context("Invalid base64 in signed_prekey")?;

    // Signed prekey should be hybrid KEM public key: X25519 (32) + ML-KEM-768 (1184) = 1216 bytes
    if prekey_bytes.len() != key_sizes::HYBRID_KEM_PUBLIC_KEY {
        return Err(anyhow::anyhow!(
            "Signed prekey must be {} bytes for hybrid suite (got {} bytes). \
             Expected: X25519 (32) + ML-KEM-768 (1184) = {} bytes",
            key_sizes::HYBRID_KEM_PUBLIC_KEY,
            prekey_bytes.len(),
            key_sizes::HYBRID_KEM_PUBLIC_KEY
        ));
    }

    // Validate one-time prekeys if present
    for (idx, otpk) in suite.one_time_prekeys.iter().enumerate() {
        let otpk_bytes = BASE64
            .decode(otpk)
            .with_context(|| format!("Invalid base64 in one_time_prekey[{}]", idx))?;

        // One-time prekey should be hybrid KEM public key: X25519 (32) + ML-KEM-768 (1184) = 1216 bytes
        if otpk_bytes.len() != key_sizes::HYBRID_KEM_PUBLIC_KEY {
            return Err(anyhow::anyhow!(
                "One-time prekey[{}] must be {} bytes for hybrid suite (got {} bytes). \
                 Expected: X25519 (32) + ML-KEM-768 (1184) = {} bytes",
                idx,
                key_sizes::HYBRID_KEM_PUBLIC_KEY,
                otpk_bytes.len(),
                key_sizes::HYBRID_KEM_PUBLIC_KEY
            ));
        }
    }

    Ok(())
}

/// Validates encrypted message ciphertext for hybrid suite
///
/// For hybrid suite, ciphertext format is:
/// ephemeral_hybrid_kem_public (1216 bytes) || ml_kem_ciphertext (1088 bytes) || cha cha20_poly1305_sealed_box
///
/// Minimum size: 1216 + 1088 + 16 (AEAD tag) = 2320 bytes
///
/// Note: This function is only called when post-quantum feature is enabled.
#[cfg(feature = "post-quantum")]
pub fn validate_hybrid_ciphertext(ciphertext: &[u8]) -> Result<()> {
    const MIN_HYBRID_CIPHERTEXT_SIZE: usize =
        key_sizes::HYBRID_KEM_PUBLIC_KEY + key_sizes::ML_KEM_768_CIPHERTEXT + 16; // 1216 + 1088 + 16 = 2320

    if ciphertext.len() < MIN_HYBRID_CIPHERTEXT_SIZE {
        return Err(anyhow::anyhow!(
            "Ciphertext too short for hybrid suite (expected at least {} bytes, got {} bytes). \
             Format: ephemeral_hybrid_kem_pub ({} bytes) || ml_kem_ct ({} bytes) || cha cha20_poly1305_sealed_box (min 16 bytes)",
            MIN_HYBRID_CIPHERTEXT_SIZE,
            ciphertext.len(),
            key_sizes::HYBRID_KEM_PUBLIC_KEY,
            key_sizes::ML_KEM_768_CIPHERTEXT
        ));
    }

    Ok(())
}

/// Validates hybrid signature format
///
/// Hybrid signature should be: Ed25519 (64 bytes) + ML-DSA-65 (3293 bytes) = 3357 bytes
///
/// Note: This function is only called when post-quantum feature is enabled.
#[cfg(feature = "post-quantum")]
pub fn validate_hybrid_signature(signature: &[u8]) -> Result<()> {
    if signature.len() != key_sizes::HYBRID_SIGNATURE {
        return Err(anyhow::anyhow!(
            "Hybrid signature must be {} bytes (got {} bytes). \
             Expected: Ed25519 (64) + ML-DSA-65 (3293) = {} bytes",
            key_sizes::HYBRID_SIGNATURE,
            signature.len(),
            key_sizes::HYBRID_SIGNATURE
        ));
    }

    Ok(())
}

/// Validates hybrid master identity key (signature public key)
///
/// Hybrid master identity key should be: Ed25519 (32 bytes) + ML-DSA-65 (1952 bytes) = 1984 bytes
///
/// Note: This function is only called when post-quantum feature is enabled.
#[cfg(feature = "post-quantum")]
pub fn validate_hybrid_master_identity_key(key: &[u8]) -> Result<()> {
    if key.len() != key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY {
        return Err(anyhow::anyhow!(
            "Hybrid master identity key must be {} bytes (got {} bytes). \
             Expected: Ed25519 (32) + ML-DSA-65 (1952) = {} bytes",
            key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY,
            key.len(),
            key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY
        ));
    }

    Ok(())
}

#[cfg(test)]
#[cfg(feature = "post-quantum")]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hybrid_suite_key_material() {
        use crate::e2e::SuiteKeyMaterial;

        let suite = SuiteKeyMaterial {
            suite_id: 2, // PQ_HYBRID_KYBER
            identity_key: BASE64.encode(vec![0u8; key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY]),
            signed_prekey: BASE64.encode(vec![0u8; key_sizes::HYBRID_KEM_PUBLIC_KEY]),
            signed_prekey_signature: BASE64.encode(vec![0u8; 64]), // Dummy Ed25519 signature
            one_time_prekeys: vec![BASE64.encode(vec![0u8; key_sizes::HYBRID_KEM_PUBLIC_KEY])],
        };

        assert!(validate_hybrid_suite_key_material(&suite).is_ok());
    }

    #[test]
    fn test_validate_hybrid_signature() {
        let valid_sig = vec![0u8; key_sizes::HYBRID_SIGNATURE];
        assert!(validate_hybrid_signature(&valid_sig).is_ok());

        let invalid_sig = vec![0u8; 100];
        assert!(validate_hybrid_signature(&invalid_sig).is_err());
    }

    #[test]
    fn test_validate_hybrid_master_identity_key() {
        let valid_key = vec![0u8; key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY];
        assert!(validate_hybrid_master_identity_key(&valid_key).is_ok());

        let invalid_key = vec![0u8; 100];
        assert!(validate_hybrid_master_identity_key(&invalid_key).is_err());
    }
}
