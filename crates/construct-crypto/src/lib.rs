//! # Construct Crypto
//!
//! Cryptographic primitives for the Construct secure messaging server.
//!
//! ## Features
//!
//! - **pqc**: Post-quantum cryptography (hybrid ECDH + Kyber)
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! construct-crypto = { version = "0.6", features = ["pqc"] }
//! ```

#![warn(missing_docs)]

pub mod key_sizes;

/// Username hashing for privacy-preserving storage (always available, no feature flag)
pub mod username;
pub use username::hash_username;

/// Generic HMAC-SHA256 hashing helper (privacy-preserving identifiers)
pub mod hmac_hash;
pub use hmac_hash::hmac_sha256;

/// Server-side envelope encryption (ChaCha20Poly1305) for at-rest protection of user identifiers.
/// Used to encrypt `from_user_id` in contact_requests without storing plaintext UUIDs.
pub mod envelope;
pub use envelope::{envelope_decrypt, envelope_encrypt};

/// ConstructPrivacyPass server-side primitives (VOPRF token redemption, sealed-box
/// opening) for stealth-sender anti-abuse. Always available, no feature flag.
pub mod privacy_pass;

/// Post-quantum cryptography (hybrid ECDH + Kyber)
#[cfg(feature = "pqc")]
pub mod pqc;

/// Signing with server keys the offline root delegated (sender certificates, KT tree heads)
#[cfg(feature = "pqc")]
pub mod server_trust;
