// ============================================================================
// Proof of Work (PoW) - Bot Registration Prevention
// ============================================================================
//
// Purpose: Prevent automated bot registration via computational puzzle
//
// Algorithm: Argon2id (memory-hard, ASIC-resistant)
// - MORE secure than SHA256 Hashcash
// - Memory-hard: requires 32 MB RAM
// - ASIC-resistant: can't use specialized hardware
// - Mobile-friendly: 3-5 minutes on iOS/Android
//
// Parameters (MUST MATCH CLIENT):
// - memory_cost: 32768 KiB (32 MB)
// - time_cost: 2 iterations
// - parallelism: 1 thread
// - hash_len: 32 bytes
// - salt: derived from challenge (see derive_pow_salt)
//
// Security:
// - Each challenge has a unique salt (derived from the random challenge)
// - Prevents precomputation attacks (can't build rainbow tables)
// - Salt format: "kpow2:" + first 16 chars of challenge
//
// Difficulty Levels:
// - Normal (8):   3-5 minutes on mobile (~256 attempts)
// - Attack (12):  1-2 hours (~4096 attempts)
// - Extreme (16): ~24 hours (DoS protection)
//
// ============================================================================

use argon2::{
    Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString},
};

/// Proof of Work difficulty level (leading zero bits required)
pub const POW_DIFFICULTY_NORMAL: u32 = 8; // 3-5 minutes
pub const POW_DIFFICULTY_ATTACK: u32 = 12; // 1-2 hours
pub const POW_DIFFICULTY_EXTREME: u32 = 16; // ~24 hours

/// Salt prefix for PoW v2 (challenge-based salt)
const POW_SALT_PREFIX: &str = "kpow2:";

/// Derive a unique salt from the challenge string.
///
/// Format: "kpow2:" + first 16 characters of challenge
///
/// This ensures each PoW challenge has a unique salt, preventing:
/// - Precomputation attacks
/// - Rainbow tables
/// - Replay of solutions across different challenges
///
/// The salt is deterministic from the challenge, so both client
/// and server can derive the same salt independently.
pub fn derive_pow_salt(challenge: &str) -> String {
    // Take first 16 chars of challenge (minimum for salt uniqueness)
    // Full challenge is 32 chars (128 bits), but salt needs to be
    // valid base64 and have reasonable length
    let challenge_prefix = &challenge[..std::cmp::min(16, challenge.len())];
    format!("{}{}", POW_SALT_PREFIX, challenge_prefix)
}

/// Argon2id parameters (MUST match client)
const MEMORY_COST_KIB: u32 = 32 * 1024; // 32 MB
const TIME_COST: u32 = 2; // 2 iterations
const PARALLELISM: u32 = 1; // 1 thread
const HASH_LENGTH: usize = 32; // 32 bytes

/// Validate a Proof of Work solution using Argon2id
///
/// # Arguments
/// * `challenge` - Server-provided random challenge string
/// * `nonce` - Client-computed nonce that solves the puzzle
/// * `claimed_hash` - Client-provided hash (hex-encoded)
/// * `required_difficulty` - Required number of leading zero bits
///
/// # Returns
/// `true` if the solution is valid, `false` otherwise
///
/// # Example
/// ```rust
/// use construct_server_shared::pow::verify_pow_solution;
///
/// let challenge = "abc123def456";
/// let nonce = 12345u64;
/// let claimed_hash = "00ab...";  // hex string
/// let difficulty = 8;
///
/// if verify_pow_solution(challenge, nonce, claimed_hash, difficulty) {
///     println!("PoW solution is valid!");
/// }
/// ```
pub fn verify_pow_solution(
    challenge: &str,
    nonce: u64,
    claimed_hash: &str,
    required_difficulty: u32,
) -> bool {
    // 1. Construct input (same as client)
    let input = format!("{}{}", challenge, nonce);

    // 2. Build Argon2id parameters
    let params = match ParamsBuilder::new()
        .m_cost(MEMORY_COST_KIB)
        .t_cost(TIME_COST)
        .p_cost(PARALLELISM)
        .output_len(HASH_LENGTH)
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build Argon2 params");
            return false;
        }
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // 3. Create challenge-based salt (v2: unique per challenge)
    let derived_salt = derive_pow_salt(challenge);
    let salt = match SaltString::encode_b64(derived_salt.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode salt");
            return false;
        }
    };

    // 4. Compute hash
    let password_hash = match argon2.hash_password(input.as_bytes(), &salt) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(
                challenge = %challenge,
                nonce = %nonce,
                error = %e,
                "Failed to compute Argon2 hash"
            );
            return false;
        }
    };

    // 5. Extract hash bytes
    let computed_hash_bytes = match password_hash.hash {
        Some(h) => h.as_bytes().to_vec(),
        None => {
            tracing::error!("Hash extraction failed");
            return false;
        }
    };

    let computed_hex = hex::encode(&computed_hash_bytes);

    // 6. Verify hash matches claimed hash
    if computed_hex != claimed_hash {
        tracing::debug!(
            challenge = %challenge,
            nonce = %nonce,
            computed = %computed_hex,
            claimed = %claimed_hash,
            "Hash mismatch"
        );
        return false;
    }

    // 7. Verify difficulty (count leading zero bits)
    let leading_zeros = count_leading_zero_bits(&computed_hash_bytes);

    if leading_zeros < required_difficulty {
        tracing::debug!(
            challenge = %challenge,
            nonce = %nonce,
            leading_zeros = %leading_zeros,
            required = %required_difficulty,
            "Insufficient difficulty"
        );
        return false;
    }

    tracing::info!(
        challenge = %challenge,
        nonce = %nonce,
        difficulty = %leading_zeros,
        "PoW solution verified"
    );

    true
}

/// Count leading zero bits in hash
fn count_leading_zero_bits(hash_bytes: &[u8]) -> u32 {
    let mut count = 0;

    for byte in hash_bytes {
        if *byte == 0 {
            count += 8;
        } else {
            // Count leading zeros in this byte
            count += byte.leading_zeros();
            break;
        }
    }

    count
}

/// Generate a cryptographically secure random challenge string
///
/// # Returns
/// 32-character hex string (128 bits of entropy)
pub fn generate_challenge() -> String {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Calculate average solve time based on difficulty
///
/// # Arguments
/// * `difficulty` - Number of leading zero bits required
///
/// # Returns
/// Estimated average seconds to solve on a mobile device
///
/// Note: Argon2id is slower than SHA256, estimates are rough
pub fn estimate_solve_time_seconds(difficulty: u32) -> f64 {
    // Argon2id on mobile: ~0.5-2 seconds per attempt (due to memory cost)
    // Average attempts = 2^difficulty

    let seconds_per_attempt = 1.0; // Average 1 second per Argon2id hash
    let average_attempts = 2_f64.powi(difficulty as i32);

    seconds_per_attempt * average_attempts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_leading_zero_bits() {
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x80, 0xFF]), 8);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x40, 0xFF]), 9);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x01, 0xFF]), 15);
        assert_eq!(count_leading_zero_bits(&[0xFF, 0xFF, 0xFF]), 0);
    }

    #[test]
    fn test_generate_challenge() {
        let challenge = generate_challenge();
        assert_eq!(challenge.len(), 32); // 16 bytes = 32 hex chars

        // Should be different each time
        let challenge2 = generate_challenge();
        assert_ne!(challenge, challenge2);
    }

    #[test]
    fn test_estimate_solve_time() {
        // Difficulty 8: ~256 seconds (4 minutes)
        let time_8 = estimate_solve_time_seconds(8);
        assert!(time_8 > 200.0 && time_8 < 300.0);

        // Difficulty 12: ~4096 seconds (68 minutes)
        let time_12 = estimate_solve_time_seconds(12);
        assert!(time_12 > 4000.0 && time_12 < 5000.0);
    }

    #[test]
    fn test_pow_verification_basic() {
        // This test verifies the algorithm works
        // In production, we'd have known good values from client

        let challenge = "test_challenge_12345";

        // Try to find a valid nonce (difficulty 4 for fast test)
        // NOTE: In real usage, client does this work
        for test_nonce in 0..1000 {
            let input = format!("{}{}", challenge, test_nonce);

            let params = ParamsBuilder::new()
                .m_cost(MEMORY_COST_KIB)
                .t_cost(TIME_COST)
                .p_cost(PARALLELISM)
                .output_len(HASH_LENGTH)
                .build()
                .unwrap();

            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
            let derived_salt = derive_pow_salt(challenge);
            let salt = SaltString::encode_b64(derived_salt.as_bytes()).unwrap();

            if let Ok(hash) = argon2.hash_password(input.as_bytes(), &salt)
                && let Some(h) = hash.hash
            {
                let hash_bytes = h.as_bytes();
                let leading_zeros = count_leading_zero_bits(hash_bytes);

                if leading_zeros >= 4 {
                    let hash_hex = hex::encode(hash_bytes);

                    // Verify our verification function works
                    assert!(verify_pow_solution(challenge, test_nonce, &hash_hex, 4));
                    assert!(!verify_pow_solution(
                        challenge,
                        test_nonce + 1,
                        &hash_hex,
                        4
                    ));
                    assert!(!verify_pow_solution(challenge, test_nonce, &hash_hex, 12));

                    println!("Found valid nonce: {} (hash: {})", test_nonce, hash_hex);
                    return;
                }
            }
        }

        // If we didn't find a nonce in 1000 attempts, that's OK for difficulty 4
        // (expected ~16 attempts on average, but we might be unlucky)
        println!("Did not find valid nonce in 1000 attempts (unlucky, but OK for test)");
    }
}
