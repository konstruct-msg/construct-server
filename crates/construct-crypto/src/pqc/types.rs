//! Size constants used by the active hybrid signature implementation.

/// Hybrid key and signature lengths.
pub mod key_sizes {
    /// X25519 public key size
    pub const X25519_PUBLIC_KEY: usize = 32;

    /// ML-KEM-768 public key size (FIPS 203)
    pub const ML_KEM_768_PUBLIC_KEY: usize = 1184;

    /// ML-KEM-768 ciphertext size
    pub const ML_KEM_768_CIPHERTEXT: usize = 1088;

    /// Hybrid KEM public key total size
    pub const HYBRID_KEM_PUBLIC_KEY: usize = X25519_PUBLIC_KEY + ML_KEM_768_PUBLIC_KEY; // 1216 bytes

    /// Ed25519 public key size
    pub const ED25519_PUBLIC_KEY: usize = 32;

    /// Ed25519 secret key seed size
    pub const ED25519_SECRET_KEY: usize = 32;

    /// Ed25519 signature size
    pub const ED25519_SIGNATURE: usize = 64;

    /// ML-DSA-65 public key size (FIPS 204)
    pub const ML_DSA_65_PUBLIC_KEY: usize = 1952;

    /// ML-DSA-65 stored secret size — the 32-byte signing seed.
    /// (The FIPS 204 expanded secret key is 4032 bytes, re-derived from the seed
    /// on demand; ml-dsa deprecated expanded import/export, so we store the seed.)
    pub const ML_DSA_65_SECRET_KEY: usize = 32;

    /// ML-DSA-65 signature size
    pub const ML_DSA_65_SIGNATURE: usize = 3309;

    /// Hybrid signature public key total size
    pub const HYBRID_SIGNATURE_PUBLIC_KEY: usize = ED25519_PUBLIC_KEY + ML_DSA_65_PUBLIC_KEY; // 1984 bytes

    /// Hybrid signature private key total size
    /// Format: [ed25519_seed (32)] [mldsa65_seed (32)] [mldsa65_pk (1952)]
    pub const HYBRID_SIG_SECRET_KEY: usize =
        ED25519_SECRET_KEY + ML_DSA_65_SECRET_KEY + ML_DSA_65_PUBLIC_KEY; // 2016 bytes

    /// Hybrid signature total size
    pub const HYBRID_SIGNATURE: usize = ED25519_SIGNATURE + ML_DSA_65_SIGNATURE;
    // 3373 bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_key_sizes() {
        assert_eq!(key_sizes::HYBRID_KEM_PUBLIC_KEY, 1216);
        assert_eq!(key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY, 1984);
        assert_eq!(key_sizes::HYBRID_SIGNATURE, 3373);
    }
}
