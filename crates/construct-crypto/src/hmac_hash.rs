//! Generic HMAC-SHA256 hashing helpers.
//!
//! Used for privacy-preserving identifiers stored on the server (e.g. username hashes,
//! contact links, dedup keys).
//!
//! The goal is deterministic, keyed hashing: the server can check membership/equality
//! without persisting plaintext identifiers.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute `HMAC-SHA256(secret, data)` and return 32 raw bytes.
///
/// # Security
/// - Deterministic (same input -> same output)
/// - One-way without `secret`
pub fn hmac_sha256(secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}
