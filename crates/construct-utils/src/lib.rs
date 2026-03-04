use hyper::header::HeaderValue;
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

    // Take first 4 bytes and format each as hex
    hash[..4]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
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

/// Adds security headers to HTTP responses
///
/// This function adds standard security headers to protect against:
/// - Clickjacking (X-Frame-Options)
/// - MIME sniffing (X-Content-Type-Options)
/// - XSS attacks (Content-Security-Policy, X-XSS-Protection)
/// - Man-in-the-middle attacks (Strict-Transport-Security, if HTTPS)
/// - Information leakage (Referrer-Policy)
/// - Unwanted browser features (Permissions-Policy)
///
/// # Arguments
/// * `headers` - Mutable reference to response headers
/// * `is_https` - Whether the connection is HTTPS (affects HSTS header)
///
/// # Note
/// This function handles header parsing errors gracefully, logging them but
/// not failing the request if a header cannot be set.
pub fn add_security_headers(headers: &mut hyper::HeaderMap, is_https: bool) {
    // Security headers for all HTTP responses
    // Note: HeaderValue::from_static() is infallible for static strings

    // 1. X-Frame-Options: Prevent clickjacking by disabling iframe embedding
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // 2. X-Content-Type-Options: Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // 3. Content-Security-Policy: Restrict resource loading (for API, allow all but prevent XSS)
    // For REST API endpoints, we use a permissive CSP since we don't serve HTML
    // This still provides some protection against injected scripts
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'; script-src 'none'; object-src 'none';"),
    );

    // 4. X-XSS-Protection: Legacy XSS protection (for older browsers)
    // Modern browsers use CSP instead, but this helps with older clients
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // 5. Referrer-Policy: Control referrer information leakage
    // strict-origin-when-cross-origin: Send full URL for same-origin, origin-only for HTTPS->HTTPS, nothing for downgrade
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // 6. Permissions-Policy: Disable unnecessary browser features
    // For API endpoints, we disable geolocation, microphone, camera, etc.
    headers.insert("Permissions-Policy", HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"));

    // 7. Strict-Transport-Security (HSTS): Force HTTPS connections (only for HTTPS responses)
    // max-age=31536000 = 1 year, includeSubDomains = apply to all subdomains
    // preload = allow inclusion in HSTS preload lists (optional but recommended for production)
    if is_https {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }
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
    // 1. Check X-Forwarded-For (first IP in chain)
    if let Some(forwarded_for) = headers.get("x-forwarded-for")
        && let Ok(forwarded_str) = forwarded_for.to_str()
    {
        // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        // We want the first (original client) IP
        let first_ip = forwarded_str.split(',').next().unwrap_or("").trim();
        if !first_ip.is_empty() {
            // Try to parse as IP address
            if let Ok(ip) = first_ip.parse::<IpAddr>() {
                return normalize_ip(ip);
            }
        }
    }

    // 2. Check X-Real-IP (single IP, often set by nginx)
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
mod tests {
    use super::*;

    #[test]
    fn test_password_too_short() {
        assert!(validate_password_strength("Short1").is_err());
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
