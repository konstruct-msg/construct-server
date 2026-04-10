/// Server-side envelope encryption for at-rest protection of user identifiers.
///
/// Uses ChaCha20Poly1305 with a random 12-byte nonce prepended to the ciphertext.
/// Wire format: nonce(12) || ciphertext(n) || tag(16)
///
/// Used to encrypt `from_user_id` (16-byte UUID) in the `contact_requests` table
/// so a DB dump without `REQUEST_ENVELOPE_KEY` reveals no plaintext UUIDs.
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, OsRng},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};

/// Encrypt `plaintext` with the given 32-byte key.
/// Returns `nonce(12) || ciphertext || tag(16)`.
pub fn envelope_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key.get(..32).ok_or("key must be 32 bytes")?);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("envelope_encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by `envelope_encrypt`.
/// Expects `nonce(12) || ciphertext || tag(16)`.
pub fn envelope_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 + 16 {
        return Err(format!(
            "envelope_decrypt: data too short ({} bytes)",
            data.len()
        ));
    }
    let key = Key::from_slice(key.get(..32).ok_or("key must be 32 bytes")?);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| format!("envelope_decrypt failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"test-user-id-uuid";
        let encrypted = envelope_encrypt(&key, plaintext).unwrap();
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
        let decrypted = envelope_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces_each_call() {
        let key = [0x11u8; 32];
        let plaintext = b"same-plaintext";
        let enc1 = envelope_encrypt(&key, plaintext).unwrap();
        let enc2 = envelope_encrypt(&key, plaintext).unwrap();
        // Nonces must differ (random)
        assert_ne!(&enc1[..12], &enc2[..12]);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [0xAAu8; 32];
        let bad_key = [0xBBu8; 32];
        let enc = envelope_encrypt(&key, b"secret").unwrap();
        assert!(envelope_decrypt(&bad_key, &enc).is_err());
    }
}
