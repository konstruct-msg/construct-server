//! Cryptographic key sizes and constants

/// Classical X25519 public key size (32 bytes)
pub const X25519_PUBLIC_KEY: usize = 32;

/// Classical Ed25519 public key size (32 bytes)
pub const ED25519_PUBLIC_KEY: usize = 32;

/// Classical Ed25519 signature size (64 bytes)
pub const ED25519_SIGNATURE: usize = 64;

/// ML-KEM-768 public key size (1184 bytes)
pub const ML_KEM_768_PUBLIC_KEY: usize = 1184;

/// ML-KEM-768 ciphertext size (1088 bytes)
pub const ML_KEM_768_CIPHERTEXT: usize = 1088;

/// ML-DSA-65 public key size (1952 bytes)
pub const ML_DSA_65_PUBLIC_KEY: usize = 1952;

/// ML-DSA-65 signature size (3309 bytes)
pub const ML_DSA_65_SIGNATURE: usize = 3309;

/// Hybrid KEM public key: X25519 + ML-KEM-768 = 32 + 1184 = 1216 bytes
pub const HYBRID_KEM_PUBLIC_KEY: usize = X25519_PUBLIC_KEY + ML_KEM_768_PUBLIC_KEY;

/// Hybrid signature public key: Ed25519 + ML-DSA-65 = 32 + 1952 = 1984 bytes
pub const HYBRID_SIGNATURE_PUBLIC_KEY: usize = ED25519_PUBLIC_KEY + ML_DSA_65_PUBLIC_KEY;

/// Hybrid signature: Ed25519 + ML-DSA-65 = 64 + 3309 = 3373 bytes
pub const HYBRID_SIGNATURE: usize = ED25519_SIGNATURE + ML_DSA_65_SIGNATURE;
