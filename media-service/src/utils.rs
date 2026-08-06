// ============================================================================
// Media Service Utilities
// ============================================================================

use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256, hex-encoded lowercase.
pub fn compute_hmac(message: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time equality for equal-length hex HMAC digests.
///
/// Returns false if either side is not valid hex or lengths differ (after decode),
/// without short-circuiting on the first differing nibble of the digest bytes.
pub fn hmac_eq(a_hex: &str, b_hex: &str) -> bool {
    let (Ok(a), Ok(b)) = (hex::decode(a_hex), hex::decode(b_hex)) else {
        return false;
    };
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(&b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip_and_ct_eq() {
        let h = compute_hmac("hello", "secret-at-least-32-chars-long!!");
        assert!(hmac_eq(&h, &h));
        assert!(!hmac_eq(&h, "00"));
        let other = compute_hmac("other", "secret-at-least-32-chars-long!!");
        assert!(!hmac_eq(&h, &other));
    }
}
