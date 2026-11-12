use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

/// A wrapper type for sensitive data (passwords, tokens, secrets) that prevents accidental logging
///
/// This type implements Debug and Display to show only "[REDACTED]" to prevent
/// sensitive data from being logged or printed.
#[derive(Clone)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn into_inner(self) -> String {
        self.inner
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// Creates a truncated, salted hash of an identifier for safe logging.
///
/// # Arguments
/// * `id` - The identifier to hash (e.g., username, user_id).
/// * `salt` - A salt value from the application's configuration.
///
/// # Returns
/// A short, hexadecimal string representing the salted hash.
pub fn log_safe_id(id: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(id.as_bytes());
    let hash = hasher.finalize();

    lower_hex(&hash[..4])
}

// One output allocation; do not build a temporary String for every byte. Width, lowercase
// alphabet and leading zeroes are part of the existing log/rate-key representation.
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 15)] as char);
    }
    output
}

/// Derives a stable, salted tag from a client IP so the **raw address is never
/// stored** — in anti-abuse rate-limit keys, logs, or audit records. Uses the same
/// secret salt as [`log_safe_id`] (`LOG_HASH_SALT`); reversing it requires that salt
/// *and* a brute force over the address space, and the raw value never appears at
/// rest. Anti-abuse semantics are unchanged: the same IP maps to the same tag, so
/// per-IP rate limits still apply.
///
/// The `"unknown"` sentinel (returned by `extract_client_ip` when no address is
/// present) passes through unchanged, so callers' `!= "unknown"` guards keep working.
/// Output is 8 bytes (64-bit) of hex — long enough to keep rate-limit buckets
/// collision-free, short enough for logs.
pub fn hash_client_ip(ip: &str, salt: &str) -> String {
    if ip == "unknown" {
        return "unknown".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"client-ip:"); // domain separation from user_id / username hashing
    hasher.update(salt.as_bytes());
    hasher.update(ip.as_bytes());
    let hash = hasher.finalize();
    lower_hex(&hash[..8])
}

/// Validates username format and length requirements.
///
/// # Username Requirements
/// - Minimum length: 3 characters
/// - Maximum length: 64 characters
/// - Allowed characters: alphanumeric (a-z, A-Z, 0-9) and underscore (_)
/// - Must start with a letter (a-z, A-Z)
///
/// # Returns
/// - `Ok(())` if username meets all requirements
/// - `Err(String)` with user-friendly error message if validation fails
pub fn validate_username(username: &str) -> Result<(), String> {
    // 1. Check minimum length
    if username.len() < 3 {
        return Err("Username must be at least 3 characters long".to_string());
    }

    // 2. Check maximum length (prevent DoS)
    if username.len() > 64 {
        return Err("Username must not exceed 64 characters".to_string());
    }

    // 3. Check that username starts with a letter
    if !username
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return Err("Username must start with a letter".to_string());
    }

    // 4. Check that all characters are alphanumeric or underscore
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("Username can only contain letters, numbers, and underscores".to_string());
    }

    Ok(())
}

/// Validates password complexity requirements.
///
/// # Password Requirements
/// - Minimum length: 10 characters
/// - At least one uppercase letter (A-Z)
/// - At least one lowercase letter (a-z)
/// - At least one digit (0-9)
///
/// # Returns
/// - `Ok(())` if password meets all requirements
/// - `Err(String)` with user-friendly error message if validation fails
///
/// # Security Note
/// We intentionally do NOT check for special characters to avoid forcing
/// users into specific password managers or causing UX friction.
/// Length + mixed case + digits provides sufficient entropy.
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    // 1. Check minimum length (10 characters for good entropy)
    if password.len() < 10 {
        return Err("Password must be at least 10 characters long".to_string());
    }

    // 2. Check for at least one uppercase letter
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }

    // 3. Check for at least one lowercase letter
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }

    // 4. Check for at least one digit
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }

    // 5. Optional: Check maximum length to prevent DoS via bcrypt
    // bcrypt has max input of 72 bytes, but we limit earlier for performance
    if password.len() > 128 {
        return Err("Password must not exceed 128 characters".to_string());
    }

    Ok(())
}

/// Validates secret key strength by checking entropy and patterns.
///
/// Checks for:
/// - Minimum length (must be at least min_length)
/// - Not all the same character (e.g., "aaaaa...")
/// - Not a simple pattern (e.g., "abcdabcd...")
/// - At least some character diversity
///
/// # Arguments
/// * `secret` - The secret key to validate
/// * `min_length` - Minimum required length
///
/// # Returns
/// - `Ok(())` if secret meets strength requirements
/// - `Err(String)` with explanation if validation fails
pub fn validate_secret_strength(secret: &str, min_length: usize) -> Result<(), String> {
    // 1. Check minimum length
    if secret.len() < min_length {
        return Err(format!(
            "Secret must be at least {} characters long",
            min_length
        ));
    }

    // 2. Check that not all characters are the same
    let first_char = secret.chars().next();
    if let Some(first) = first_char
        && secret.chars().all(|c| c == first)
    {
        return Err("Secret must not consist of a single repeated character".to_string());
    }

    // 3. Check for simple repeating patterns (e.g., "ababab" or "123123")
    if secret.len() >= 4 {
        // Check 2-character patterns
        for pattern_len in 2..=(secret.len() / 2).min(8) {
            let pattern = &secret[..pattern_len];
            let repetitions = secret.len() / pattern_len;
            let repeated = pattern.repeat(repetitions);
            if secret.starts_with(&repeated) {
                return Err("Secret must not contain simple repeating patterns".to_string());
            }
        }
    }

    // 4. Check character diversity - should have at least 8 unique characters for secrets >= 32 bytes
    if secret.len() >= 32 {
        let unique_chars: HashSet<char> = secret.chars().collect();
        if unique_chars.len() < 8 {
            return Err("Secret must contain at least 8 different characters".to_string());
        }
    }

    Ok(())
}

/// Extracts client IP address from HTTP request headers
///
/// Checks headers in order of priority:
/// 1. X-Forwarded-For (first IP in the chain, if present)
/// 2. X-Real-IP (single IP, if present)
/// 3. Falls back to provided direct IP (from connection)
///
/// # Security Note
/// X-Forwarded-For can be spoofed by clients, so it should only be trusted
/// if the request comes through a trusted proxy/load balancer.
/// In production, ensure your reverse proxy (Caddy, nginx, etc.) sets these headers
/// and strips any existing X-Forwarded-For from untrusted sources.
///
/// # Arguments
/// * `headers` - HTTP request headers
/// * `direct_ip` - Direct connection IP (fallback if headers don't contain IP)
///
/// # Returns
/// IP address as a string (normalized, without brackets for IPv6)
pub fn extract_client_ip(headers: &axum::http::HeaderMap, direct_ip: Option<IpAddr>) -> String {
    // 1. X-Forwarded-For: take the **rightmost** hop. With a single trusted edge
    // (Caddy) that *appends* the peer IP, rightmost is the real connecting client;
    // leftmost is attacker-controlled if the client pre-sets the header.
    if let Some(forwarded_for) = headers.get("x-forwarded-for")
        && let Ok(forwarded_str) = forwarded_for.to_str()
    {
        let hop = forwarded_str.split(',').next_back().unwrap_or("").trim();
        if !hop.is_empty()
            && let Ok(ip) = hop.parse::<IpAddr>()
        {
            return normalize_ip(ip);
        }
    }

    // 2. X-Real-IP (single IP, often set by nginx/Caddy)
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(real_ip_str) = real_ip.to_str()
        && let Ok(ip) = real_ip_str.trim().parse::<IpAddr>()
    {
        return normalize_ip(ip);
    }

    // 3. Fallback to direct connection IP
    if let Some(ip) = direct_ip {
        return normalize_ip(ip);
    }

    // 4. Last resort: return "unknown" (shouldn't happen in production)
    "unknown".to_string()
}

/// Normalizes IP address to string format (removes brackets for IPv6)
fn normalize_ip(ip: IpAddr) -> String {
    let ip_str = ip.to_string();
    // Remove brackets if present (e.g., "[::1]" -> "::1")
    ip_str
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

#[cfg(test)]
mod audit_239 {
    use super::*;
    #[test]
    fn forwarded_ip_uses_only_the_rightmost_valid_hop_then_real_then_direct() {
        let direct: IpAddr = "192.0.2.3".parse().unwrap();
        for (xff, real, expected) in [
            (
                Some("203.0.113.9, 192.0.2.1"),
                Some("192.0.2.2"),
                "192.0.2.1",
            ),
            (Some("203.0.113.9, 2001:db8::1"), None, "2001:db8::1"),
            (
                Some("203.0.113.9, invalid"),
                Some(" 192.0.2.2 "),
                "192.0.2.2",
            ),
            (Some("203.0.113.9, "), None, "192.0.2.3"),
            (Some("bad"), Some("bad"), "192.0.2.3"),
            (None, Some("2001:db8::2"), "2001:db8::2"),
            (None, None, "192.0.2.3"),
        ] {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(s) = xff {
                headers.insert("x-forwarded-for", s.parse().unwrap());
            }
            if let Some(s) = real {
                headers.insert("x-real-ip", s.parse().unwrap());
            }
            assert_eq!(extract_client_ip(&headers, Some(direct)), expected);
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(extract_client_ip(&headers, Some(direct)), "192.0.2.3");
        assert_eq!(
            extract_client_ip(&axum::http::HeaderMap::new(), None),
            "unknown"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_too_short() {
        assert!(validate_password_strength("Short1").is_err());
    }

    #[test]
    fn lower_hex_preserves_every_byte_and_leading_zero() {
        let bytes: Vec<u8> = (0..=255).collect();
        let legacy: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(lower_hex(&bytes), legacy);
        assert_eq!(lower_hex(&[]), "");
        assert_eq!(lower_hex(&[0, 1, 15, 16, 128, 255]), "00010f1080ff");
    }

    #[test]
    fn logging_hash_bytes_keep_their_existing_wire_and_key_meaning() {
        for (id, salt, expected) in [
            ("", "", "e3b0c442"),
            ("alice", "salt", "3baa379b"),
            ("用户", "salt", "2eca841b"),
            ("alice", "🔐", "dad47f26"),
        ] {
            assert_eq!(log_safe_id(id, salt), expected);
        }
        for (ip, salt, expected) in [
            ("", "", "44ca7d91c47de98c"),
            ("192.0.2.3", "salt", "23181e8ad240495d"),
            ("2001:db8::1", "salt", "5a57b10d70b884c2"),
            ("unknown", "salt", "unknown"),
        ] {
            assert_eq!(hash_client_ip(ip, salt), expected);
        }
    }

    #[test]
    fn test_hash_client_ip_stable_and_opaque() {
        let salt = "test-salt";
        let a = hash_client_ip("1.2.3.4", salt);
        // Stable: same IP + salt → same tag (rate-limit keying relies on this).
        assert_eq!(a, hash_client_ip("1.2.3.4", salt));
        // Opaque: the raw address does not appear in the tag.
        assert!(!a.contains("1.2.3.4"));
        assert_eq!(a.len(), 16); // 8 bytes hex
        // Different IPs and different salts diverge.
        assert_ne!(a, hash_client_ip("1.2.3.5", salt));
        assert_ne!(a, hash_client_ip("1.2.3.4", "other-salt"));
        // Sentinel passes through so `!= "unknown"` guards keep working.
        assert_eq!(hash_client_ip("unknown", salt), "unknown");
    }

    #[test]
    fn test_password_no_uppercase() {
        assert!(validate_password_strength("lowercase123").is_err());
    }

    #[test]
    fn test_password_no_lowercase() {
        assert!(validate_password_strength("UPPERCASE123").is_err());
    }

    #[test]
    fn test_password_no_digit() {
        assert!(validate_password_strength("NoDigitsHere").is_err());
    }

    #[test]
    fn test_password_valid() {
        assert!(validate_password_strength("ValidPass123").is_ok());
        assert!(validate_password_strength("AnotherGood1").is_ok());
        assert!(validate_password_strength("MySecurePassword2024").is_ok());
    }

    #[test]
    fn test_password_too_long() {
        let long_password = "A".repeat(129) + "a1";
        assert!(validate_password_strength(&long_password).is_err());
    }

    #[test]
    fn test_username_too_short() {
        assert!(validate_username("ab").is_err());
        assert!(validate_username("a").is_err());
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_username_too_long() {
        let long_username = "a".repeat(65);
        assert!(validate_username(&long_username).is_err());
    }

    #[test]
    fn test_username_starts_with_digit() {
        assert!(validate_username("123user").is_err());
    }

    #[test]
    fn test_username_starts_with_underscore() {
        assert!(validate_username("_user").is_err());
    }

    #[test]
    fn test_username_invalid_characters() {
        assert!(validate_username("user-name").is_err());
        assert!(validate_username("user.name").is_err());
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
    }

    #[test]
    fn test_username_valid() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("Alice123").is_ok());
        assert!(validate_username(&"a".repeat(64)).is_ok()); // Max length
    }

    #[test]
    fn test_secret_all_same_char() {
        assert!(validate_secret_strength(&"a".repeat(32), 32).is_err());
        assert!(validate_secret_strength(&"0".repeat(32), 32).is_err());
    }

    #[test]
    fn test_secret_repeating_pattern() {
        assert!(validate_secret_strength(&"ab".repeat(16), 32).is_err());
        assert!(validate_secret_strength(&"1234".repeat(8), 32).is_err());
    }

    #[test]
    fn test_secret_too_short() {
        assert!(validate_secret_strength("short", 32).is_err());
    }

    #[test]
    fn test_secret_low_diversity() {
        // Only 4 unique characters in 32-char string
        let weak = "abcd".repeat(8);
        assert!(validate_secret_strength(&weak, 32).is_err());
    }

    #[test]
    fn test_secret_valid() {
        // Random-looking secret with good diversity
        let good = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        assert!(validate_secret_strength(good, 32).is_ok());

        // Base64-like secret
        let b64 = "dGVzdC1zZWVkLWZvci1lZDI1NTE5LWtleXMtMzJi";
        assert!(validate_secret_strength(b64, 32).is_ok());
    }

    #[test]
    fn test_secure_string_redacted() {
        let secret = SecureString::new("my_secret_password".to_string());
        assert_eq!(format!("{:?}", secret), "[REDACTED]");
        assert_eq!(format!("{}", secret), "[REDACTED]");
        assert_eq!(secret.as_str(), "my_secret_password");
    }
}

pub mod net;
