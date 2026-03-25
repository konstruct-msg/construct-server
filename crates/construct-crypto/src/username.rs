//! Username hashing for privacy-preserving storage.
//!
//! The server stores `HMAC-SHA256(server_secret, normalised_username)` — a
//! deterministic, keyed hash. The plaintext username is never written to disk.
//!
//! # Security properties
//! - One-way: cannot reverse the hash without `server_secret`
//! - Deterministic: same input always produces the same 32-byte output
//! - Collision-resistant: SHA-256 provides 128-bit second-preimage resistance
//! - Dictionary-attack resistant: the HMAC key makes offline brute-force infeasible
//!   without the server secret even if the DB is leaked
//!
//! # Normalisation
//! Input is trimmed and lowercased before hashing so that `Alice`, `alice`, and
//! ` alice ` all map to the same hash.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute `HMAC-SHA256(secret, trim(lowercase(username)))`.
///
/// Returns 32 raw bytes — store as `BYTEA` in PostgreSQL.
///
/// # Arguments
/// * `secret` — server-side HMAC key (`USERNAME_HMAC_SECRET`, 32 bytes recommended)
/// * `username` — plaintext username as typed by the user
///
/// # Panics
/// Never — HMAC accepts keys of any length.
pub fn hash_username(secret: &[u8], username: &str) -> Vec<u8> {
    let normalised = username.trim().to_lowercase();
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(normalised.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
