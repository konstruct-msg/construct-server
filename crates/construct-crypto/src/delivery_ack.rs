use hex;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 hash of message ID for anonymous storage
///
/// # Security Properties
/// - One-way function: cannot reverse hash to get message_id
/// - Requires SECRET_KEY to compute or verify
/// - Collision resistance: SHA256 provides 128-bit security
///
/// # Arguments
/// * `message_id` - The message ID to hash (typically UUIDv4)
/// * `secret_key` - Secret key for HMAC (should be 32 bytes)
///
/// # Returns
/// Hex-encoded hash string (64 characters)
///
/// # Example
/// ```
/// use construct_crypto::compute_message_hash;
/// let secret_key = b"01234567890123456789012345678901"; // 32 bytes
/// let hash = compute_message_hash("550e8400-e29b-41d4-a716-446655440000", secret_key);
/// assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
/// ```
pub fn compute_message_hash(message_id: &str, secret_key: &[u8]) -> String {
    // SECURITY: Validate key size before use (though HMAC accepts any size, we want 32 bytes)
    // Note: This is a defensive check - HMAC-SHA256 can technically accept any key size
    // but using exactly 32 bytes (256 bits) provides optimal security
    if secret_key.len() != 32 {
        tracing::warn!(
            key_size = secret_key.len(),
            "DELIVERY_SECRET_KEY should be exactly 32 bytes for optimal security"
        );
    }

    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC can take key of any size (validated above)");

    mac.update(message_id.as_bytes());

    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Validates that a message ID matches the expected hash
///
/// # Arguments
/// * `message_id` - The message ID to validate
/// * `message_hash` - The expected hash to compare against
/// * `secret_key` - Secret key for HMAC
///
/// # Returns
/// `true` if the hash matches, `false` otherwise
///
/// # Security Note
/// Uses constant-time comparison to prevent timing attacks
pub fn verify_message_hash(message_id: &str, message_hash: &str, secret_key: &[u8]) -> bool {
    let computed_hash = compute_message_hash(message_id, secret_key);

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    computed_hash
        .as_bytes()
        .ct_eq(message_hash.as_bytes())
        .into()
}

/// Computes HMAC-SHA256 hash of user ID for anonymous ACK routing
///
/// This is used in Kafka-based Delivery ACK (Solution 1D) to hash
/// sender_id and recipient_id before storing in Kafka events.
///
/// # Security Properties
/// - One-way function: cannot reverse hash to get user_id
/// - Same security properties as compute_message_hash
/// - Uses same SECRET_KEY for consistency
///
/// # Arguments
/// * `user_id` - The user ID to hash (UUID string)
/// * `secret_key` - Secret key for HMAC (should be 32 bytes)
///
/// # Returns
/// Hex-encoded hash string (64 characters)
///
/// # Example
/// ```ignore
/// let sender_hash = compute_user_id_hash("550e8400-e29b-41d4-a716-446655440000", &secret_key);
/// // Store in Redis: "sender_hash:{hash}" → "plaintext_uuid" (TTL 7 days)
/// ```
pub fn compute_user_id_hash(user_id: &str, secret_key: &[u8]) -> String {
    // SECURITY: Validate key size before use (defensive check)
    if secret_key.len() != 32 {
        tracing::warn!(
            key_size = secret_key.len(),
            "DELIVERY_SECRET_KEY should be exactly 32 bytes for optimal security"
        );
    }

    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC can take key of any size (validated above)");

    mac.update(user_id.as_bytes());

    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_message_hash() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let message_id = "550e8400-e29b-41d4-a716-446655440000";

        let hash = compute_message_hash(message_id, secret);

        // Should be 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);

        // Should be deterministic
        let hash2 = compute_message_hash(message_id, secret);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_messages_produce_different_hashes() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let message_id1 = "550e8400-e29b-41d4-a716-446655440000";
        let message_id2 = "550e8400-e29b-41d4-a716-446655440001";

        let hash1 = compute_message_hash(message_id1, secret);
        let hash2 = compute_message_hash(message_id2, secret);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_different_secrets_produce_different_hashes() {
        let secret1 = b"test_secret_key_32_bytes_long!!!";
        let secret2 = b"different_secret_key_32_bytes!!!";
        let message_id = "550e8400-e29b-41d4-a716-446655440000";

        let hash1 = compute_message_hash(message_id, secret1);
        let hash2 = compute_message_hash(message_id, secret2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_message_hash() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let message_id = "550e8400-e29b-41d4-a716-446655440000";

        let hash = compute_message_hash(message_id, secret);

        // Valid hash should verify
        assert!(verify_message_hash(message_id, &hash, secret));

        // Invalid hash should not verify
        let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_message_hash(message_id, fake_hash, secret));

        // Wrong message ID should not verify
        let wrong_id = "550e8400-e29b-41d4-a716-446655440001";
        assert!(!verify_message_hash(wrong_id, &hash, secret));
    }
}
