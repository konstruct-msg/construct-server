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

/// Post-quantum cryptography types and constants
pub mod types;

/// Post-quantum cryptography validation utilities
pub mod validation;

pub use types::*;
