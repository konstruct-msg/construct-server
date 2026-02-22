//! # Construct Crypto
//!
//! Cryptographic primitives for the Construct secure messaging server.
//!
//! ## Features
//!
//! - **e2ee**: End-to-end encryption primitives (Signal Protocol)
//! - **delivery-ack**: Privacy-preserving delivery acknowledgments with HMAC
//! - **pqc**: Post-quantum cryptography (hybrid ECDH + Kyber)
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! construct-crypto = { version = "0.5", features = ["e2ee", "delivery-ack"] }
//! ```

#![warn(missing_docs)]

pub mod key_sizes;

/// End-to-end encryption primitives (Signal Protocol)
#[cfg(feature = "e2ee")]
pub mod e2e;

/// Privacy-preserving delivery acknowledgments with HMAC
#[cfg(feature = "delivery-ack")]
pub mod delivery_ack;

/// Post-quantum cryptography (hybrid ECDH + Kyber)
#[cfg(feature = "pqc")]
pub mod pqc;

// Re-export commonly used types
#[cfg(feature = "e2ee")]
pub use e2e::{
    BundleData, EncryptedMessage, MessageType, ServerCryptoValidator, StoredEncryptedMessage,
    SuiteKeyMaterial, UploadableKeyBundle,
};

#[cfg(feature = "delivery-ack")]
pub use delivery_ack::{compute_message_hash, compute_user_id_hash, verify_message_hash};
