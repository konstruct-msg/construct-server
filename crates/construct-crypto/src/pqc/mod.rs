// ============================================================================
// Post-Quantum Cryptography Module
// ============================================================================
//
// Foundation for post-quantum hybrid cryptography implementation.
// This module provides types and utilities for ML-KEM (Kyber) and ML-DSA (Dilithium)
// as specified in NIST FIPS 203 and FIPS 204.
//
// Architecture:
// - Hybrid approach: Classical + Post-Quantum algorithms combined
// - Security: MIN(Classical, PQ) - both must be broken for compromise
// - Backward compatible: Classical suite remains supported
//
// Feature flag: Enable with `cargo build --features post-quantum`
//
// ============================================================================

/// Hybrid post-quantum key encapsulation and signatures
#[cfg(feature = "post-quantum")]
pub mod hybrid;

#[cfg(feature = "post-quantum")]
pub use hybrid::{
    build_prekey_sign_message,
    generate_hybrid_signature_keypair,
    hybrid_sign,
    verify_hybrid_kyber_key_signature,
    verify_hybrid_signature,
    verify_kyber_key_signature,
    // Size constants
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SECRET_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    HYBRID_SIGNATURE_SIZE,
    HYBRID_SIG_PUBLIC_KEY_SIZE,
    HYBRID_SIG_SECRET_KEY_SIZE,
    ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SECRET_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE,
};

/// Post-quantum cryptography types and constants
pub mod types;

/// Post-quantum cryptography validation utilities
pub mod validation;

pub use types::*;
