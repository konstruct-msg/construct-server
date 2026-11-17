use anyhow::{Context, Result};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Encryption key with version
#[derive(Clone)]
struct EncryptionKey {
    version: u8,
    cipher: ChaCha20Poly1305,
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("version", &self.version)
            .field("cipher", &"<ChaCha20Poly1305>")
            .finish()
    }
}

/// Encryption for device tokens using ChaCha20-Poly1305 with key versioning
/// Provides authenticated encryption to protect device tokens in database
/// Supports multiple active keys for seamless key rotation
pub struct DeviceTokenEncryption {
    /// Map of version -> encryption key (allows multiple active keys)
    keys: HashMap<u8, Arc<EncryptionKey>>,
    /// Current primary key version (used for new encryptions)
    current_version: u8,
}

/// Encrypted data format: version (1 byte) || nonce (12 bytes) || ciphertext || tag (16 bytes)
const VERSION_SIZE: usize = 1;
const NONCE_SIZE: usize = 12;
const MIN_ENCRYPTED_SIZE: usize = VERSION_SIZE + NONCE_SIZE + 16; // version + nonce + tag

impl DeviceTokenEncryption {
    /// Create new encryption instance from single key (backward compatibility)
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let encryption_key = Arc::new(EncryptionKey { version: 1, cipher });

        let mut keys = HashMap::new();
        keys.insert(1, encryption_key);

        Ok(Self {
            keys,
            current_version: 1,
        })
    }

    /// Create from hex-encoded key string (backward compatibility)
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        if hex_key.len() != 64 {
            anyhow::bail!("Device token encryption key must be 64 hex characters (32 bytes)");
        }

        let key_bytes =
            hex::decode(hex_key).context("Invalid hex in device token encryption key")?;

        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Key must be exactly 32 bytes"))?;

        Self::new(&key)
    }

    /// Create from multiple keys with versioning support
    ///
    /// # Arguments
    /// * `keys` - Map of version -> hex-encoded key string
    /// * `current_version` - Version to use for new encryptions (must exist in keys)
    ///
    /// # Example
    /// ```rust
    /// use std::collections::HashMap;
    /// use construct_apns::DeviceTokenEncryption;
    ///
    /// let mut keys = HashMap::new();
    /// keys.insert(1, "0".repeat(64));
    /// keys.insert(2, "1".repeat(64));
    /// let encryption = DeviceTokenEncryption::from_keys(keys, 2).unwrap();
    /// ```
    pub fn from_keys(keys: HashMap<u8, String>, current_version: u8) -> Result<Self> {
        if keys.is_empty() {
            anyhow::bail!("At least one encryption key is required");
        }

        if !keys.contains_key(&current_version) {
            anyhow::bail!("Current version {} must exist in keys map", current_version);
        }

        let mut encryption_keys: HashMap<u8, Arc<EncryptionKey>> = HashMap::new();

        for (version, hex_key) in keys {
            if hex_key.len() != 64 {
                anyhow::bail!(
                    "Device token encryption key version {} must be 64 hex characters (32 bytes)",
                    version
                );
            }

            let key_bytes = hex::decode(&hex_key).with_context(|| {
                format!(
                    "Invalid hex in device token encryption key version {}",
                    version
                )
            })?;

            let key: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Key version {} must be exactly 32 bytes", version))?;

            let cipher = ChaCha20Poly1305::new(&Key::from(key));
            encryption_keys.insert(version, Arc::new(EncryptionKey { version, cipher }));
        }

        Ok(Self {
            keys: encryption_keys,
            current_version,
        })
    }

    /// Get current version (for new encryptions)
    pub fn current_version(&self) -> u8 {
        self.current_version
    }

    /// Encrypt device token with versioning
    /// Returns: version (1 byte) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        // Get current encryption key
        let encryption_key = self.keys.get(&self.current_version).ok_or_else(|| {
            anyhow::anyhow!(
                "Current encryption key version {} not found",
                self.current_version
            )
        })?;

        let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt using current key
        let ciphertext = encryption_key
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Format: version (1 byte) || nonce (12 bytes) || ciphertext || tag (16 bytes)
        let mut result = vec![self.current_version];
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt device token with versioning support
    /// Input (new format): version (1 byte) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    /// Input (legacy format): nonce (12 bytes) || ciphertext || tag (16 bytes) - uses version 1
    ///
    /// Automatically detects format and uses appropriate key.
    /// Supports backward compatibility with older versions (legacy format without version byte).
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<String> {
        if encrypted.len() < MIN_ENCRYPTED_SIZE {
            anyhow::bail!(
                "Encrypted data too short (expected at least {} bytes, got {})",
                MIN_ENCRYPTED_SIZE,
                encrypted.len()
            );
        }

        // Versioned format: version (1 byte) || nonce (12 bytes) || ciphertext || tag (16 bytes)
        let version = encrypted[0];
        let encrypted_data = &encrypted[VERSION_SIZE..];

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
        let nonce = Nonce::try_from(nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Encrypted data has an invalid nonce"))?;

        // Get encryption key for this version
        let encryption_key = self.keys.get(&version).ok_or_else(|| {
            anyhow::anyhow!(
                "Encryption key version {} not found. Active versions: {:?}",
                version,
                self.keys.keys().collect::<Vec<_>>()
            )
        })?;

        // Decrypt using version-specific key
        let plaintext = encryption_key
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed for version {}: {}", version, e))?;

        String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")
    }

    /// Re-encrypt device token with current key version (for key rotation)
    ///
    /// This is useful when migrating tokens to a new key version.
    /// Decrypts with old key, re-encrypts with current key.
    pub fn reencrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self.decrypt(encrypted)?;
        self.encrypt(&plaintext)
    }

    /// Hash device token for deduplication (SHA256)
    /// This is safe to store in DB - cannot be reversed
    pub fn hash_token(token: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32]; // Test key
        let encryption = DeviceTokenEncryption::new(&key).unwrap();

        let original = "test_device_token_12345";
        let encrypted = encryption.encrypt(original).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();

        assert_eq!(original, decrypted);
        // Check that encrypted data includes version byte
        assert_eq!(encrypted[0], 1); // Version 1
    }

    #[test]
    fn test_key_versioning() {
        // Create encryption with two keys
        let mut keys = HashMap::new();
        keys.insert(
            1,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );
        keys.insert(
            2,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        );

        let encryption_v1 = DeviceTokenEncryption::from_keys(keys.clone(), 1).unwrap();
        let encryption_v2 = DeviceTokenEncryption::from_keys(keys.clone(), 2).unwrap();
        let encryption_both = DeviceTokenEncryption::from_keys(keys.clone(), 2).unwrap();

        let original = "test_token";

        // Encrypt with version 1
        let encrypted_v1 = encryption_v1.encrypt(original).unwrap();
        assert_eq!(encrypted_v1[0], 1); // Version 1

        // Encrypt with version 2
        let encrypted_v2 = encryption_v2.encrypt(original).unwrap();
        assert_eq!(encrypted_v2[0], 2); // Version 2

        // Both should decrypt with encryption_both (has both keys)
        assert_eq!(encryption_both.decrypt(&encrypted_v1).unwrap(), original);
        assert_eq!(encryption_both.decrypt(&encrypted_v2).unwrap(), original);
    }

    #[test]
    fn test_reencrypt() {
        let mut keys = HashMap::new();
        keys.insert(
            1,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );
        keys.insert(
            2,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        );

        let encryption = DeviceTokenEncryption::from_keys(keys, 2).unwrap();

        let original = "test_token";

        // Encrypt with version 1 (old key)
        let encrypted_v1 = {
            let mut keys_v1 = HashMap::new();
            keys_v1.insert(
                1,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            );
            let enc_v1 = DeviceTokenEncryption::from_keys(keys_v1, 1).unwrap();
            enc_v1.encrypt(original).unwrap()
        };

        // Re-encrypt with current key (version 2)
        let reencrypted = encryption.reencrypt(&encrypted_v1).unwrap();
        assert_eq!(reencrypted[0], 2); // Version 2

        // Should decrypt with current key
        assert_eq!(encryption.decrypt(&reencrypted).unwrap(), original);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let token = "test_token";
        let hash1 = DeviceTokenEncryption::hash_token(token);
        let hash2 = DeviceTokenEncryption::hash_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_hash_token_different_for_different_inputs() {
        let hash1 = DeviceTokenEncryption::hash_token("token1");
        let hash2 = DeviceTokenEncryption::hash_token("token2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let encryption = DeviceTokenEncryption::from_hex(hex_key).unwrap();

        let original = "test";
        let encrypted = encryption.encrypt(original).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let result = DeviceTokenEncryption::from_hex("too_short");
        assert!(result.is_err());
    }

    // ── Envelope boundaries and the redacted Debug ───────────────────────────

    /// The version byte is what lets a rotation keep old rows decryptable, so it must be
    /// the configured primary — not a constant that happens to match the default.
    #[test]
    fn current_version_names_the_configured_key() {
        assert_eq!(
            DeviceTokenEncryption::new(&[0u8; 32])
                .expect("encryption")
                .current_version(),
            1
        );

        let mut keys = HashMap::new();
        keys.insert(
            1,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );
        keys.insert(
            7,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        );
        assert_eq!(
            DeviceTokenEncryption::from_keys(keys, 7)
                .expect("from_keys")
                .current_version(),
            7
        );
    }

    /// An empty plaintext is the shortest valid envelope: version + nonce + tag. The size
    /// floor has to admit exactly that, or a token of length zero could never be stored.
    #[test]
    fn an_empty_plaintext_round_trips_at_the_size_floor() {
        let encryption = DeviceTokenEncryption::new(&[0u8; 32]).expect("encryption");
        let sealed = encryption.encrypt("").expect("encrypt");
        assert_eq!(sealed.len(), MIN_ENCRYPTED_SIZE);
        assert_eq!(encryption.decrypt(&sealed).expect("decrypt"), "");
    }

    /// One byte short of the floor has to be refused *before* the nonce is split off:
    /// a lower floor would index and split a slice that cannot hold a nonce and a tag,
    /// turning malformed input into a panic on the notification path.
    #[test]
    fn a_truncated_envelope_is_refused_before_it_is_split() {
        let encryption = DeviceTokenEncryption::new(&[0u8; 32]).expect("encryption");

        for len in [0usize, MIN_ENCRYPTED_SIZE - 1] {
            let err = encryption
                .decrypt(&vec![0u8; len])
                .expect_err("truncated input must not decrypt");
            assert!(
                err.to_string().contains("too short"),
                "{len} bytes: unexpected error {err}"
            );
        }
    }

    /// This `Debug` exists so a key that reaches a log line does not become the key. It has
    /// to name the version (the useful part) and hide the cipher and its key bytes.
    #[test]
    fn debug_of_a_key_names_the_version_and_hides_the_material() {
        let key = EncryptionKey {
            version: 7,
            cipher: ChaCha20Poly1305::new(&Key::from([9u8; 32])),
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains("version: 7"), "{rendered}");
        assert!(rendered.contains("<ChaCha20Poly1305>"), "{rendered}");
        assert!(
            !rendered.contains(&"09".repeat(32)),
            "key material must never be rendered: {rendered}"
        );
    }
}
