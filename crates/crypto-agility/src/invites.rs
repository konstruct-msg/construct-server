use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Invite token object for one-time contact sharing (v1/v2)
///
/// This structure is cryptographically signed by the user's Identity Key
/// and can be encoded into QR codes or deep links for secure contact exchange.
///
/// Protocol versions:
/// - v1: userId only (backwards compatible)
/// - v2: userId + deviceId (for device-based key fetching)
///
/// Security properties:
/// - One-time use only (jti tracking prevents replay)
/// - Short TTL (5 minutes for QR, configurable for links)
/// - Cryptographic authenticity (Ed25519 signature)
/// - Federation-ready (includes server FQDN)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteToken {
    /// Protocol version: 1 or 2
    pub v: u32,

    /// Unique invite ID (JWT jti) - prevents replay attacks
    pub jti: Uuid,

    /// User UUID who created this invite
    pub uuid: Uuid,

    /// Device ID (v2 only) - 32-char lowercase hex string
    /// None for v1 invites (backwards compat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// Server FQDN (e.g., "konstruct.cc") for federation
    pub server: String,

    /// Ephemeral X25519 public key (Base64 encoded)
    /// Generated fresh for each invite, never reused
    pub eph_key: String,

    /// Unix timestamp when this invite was created
    pub ts: i64,

    /// Ed25519 signature over canonical form
    /// v1: (v, jti, uuid, server, ephKey, ts)
    /// v2: (v, jti, uuid, deviceId, server, ephKey, ts)
    /// Signed with user's long-term Identity Key
    pub sig: String,
}

/// Validation errors for invite tokens
#[derive(Debug, Error)]
pub enum InviteValidationError {
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("Invalid JTI format")]
    InvalidJTI,

    #[error("Invalid user UUID format")]
    InvalidUserUUID,

    #[error("Invalid device ID format (must be 32-char lowercase hex)")]
    InvalidDeviceID,

    #[error("Missing device ID for v2 invite")]
    MissingDeviceID,

    #[error("Invalid server FQDN")]
    InvalidServer,

    #[error("Invalid ephemeral key")]
    InvalidEphemeralKey,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("Invite expired")]
    Expired,

    #[error("Future timestamp (clock skew attack)")]
    FutureTimestamp,

    #[error("Invalid signature format")]
    InvalidSignature,
}

impl InviteToken {
    /// Create canonical string for signature verification
    ///
    /// Format depends on protocol version:
    /// - v1: `v|jti|uuid|server|ephKey|ts`
    /// - v2: `v|jti|uuid|deviceId|server|ephKey|ts`
    ///
    /// This ensures consistent signing/verification across implementations
    pub fn canonical_string(&self) -> String {
        match self.v {
            1 => {
                // v1: Without deviceId
                format!(
                    "{}|{}|{}|{}|{}|{}",
                    self.v, self.jti, self.uuid, self.server, self.eph_key, self.ts
                )
            }
            2 => {
                // v2: With deviceId
                let device_id = self
                    .device_id
                    .as_ref()
                    .expect("deviceId required for v2 invites");
                format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    self.v, self.jti, self.uuid, device_id, self.server, self.eph_key, self.ts
                )
            }
            _ => panic!("Unsupported invite version: {}", self.v),
        }
    }

    /// Check if invite is expired
    ///
    /// Default TTL: 5 minutes (300 seconds)
    pub fn is_expired(&self, ttl_seconds: i64) -> bool {
        let now = Utc::now().timestamp();
        (now - self.ts) > ttl_seconds
    }

    /// Check if timestamp is in the future (clock skew attack)
    pub fn is_future(&self) -> bool {
        let now = Utc::now().timestamp();
        self.ts > (now + 60) // Allow 60s clock skew
    }

    /// Validate invite structure (format checks only, not signature)
    ///
    /// Checks:
    /// - Version is 1 or 2
    /// - JTI is valid UUID
    /// - User UUID is valid
    /// - Device ID format (v2 only): 32-char lowercase hex
    /// - Server FQDN is non-empty and contains a dot
    /// - Ephemeral key is valid Base64 (32 bytes)
    /// - Signature is valid Base64 (64 bytes)
    pub fn validate(&self) -> Result<(), InviteValidationError> {
        // Version check
        if self.v != 1 && self.v != 2 {
            return Err(InviteValidationError::UnsupportedVersion(self.v));
        }

        // Device ID validation (required for v2)
        if self.v == 2 {
            match &self.device_id {
                None => return Err(InviteValidationError::MissingDeviceID),
                Some(device_id) => {
                    // Must be 32-char lowercase hex string (0-9, a-f)
                    if device_id.len() != 32 {
                        return Err(InviteValidationError::InvalidDeviceID);
                    }
                    if !device_id
                        .chars()
                        .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
                    {
                        return Err(InviteValidationError::InvalidDeviceID);
                    }
                }
            }
        }

        // Server FQDN (basic check)
        if self.server.is_empty() || !self.server.contains('.') {
            return Err(InviteValidationError::InvalidServer);
        }

        // Ephemeral key (Base64, should decode to 32 bytes)
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        match STANDARD.decode(&self.eph_key) {
            Ok(bytes) if bytes.len() == 32 => {}
            _ => return Err(InviteValidationError::InvalidEphemeralKey),
        }

        // Timestamp checks
        let now = Utc::now().timestamp();
        if self.ts <= 0 || self.ts > now + 300 {
            // 5 min clock skew
            return Err(InviteValidationError::InvalidTimestamp);
        }

        // Signature (Base64, should decode to 64 bytes)
        match STANDARD.decode(&self.sig) {
            Ok(bytes) if bytes.len() == 64 => {}
            _ => return Err(InviteValidationError::InvalidSignature),
        }

        Ok(())
    }

    /// Full validation including expiry check
    pub fn validate_with_expiry(&self, ttl_seconds: i64) -> Result<(), InviteValidationError> {
        self.validate()?;

        if self.is_expired(ttl_seconds) {
            return Err(InviteValidationError::Expired);
        }

        if self.is_future() {
            return Err(InviteValidationError::FutureTimestamp);
        }

        Ok(())
    }
}

/// Database record for invite token tracking
#[derive(Debug, Clone)]
pub struct InviteTokenRecord {
    pub jti: Uuid,
    pub user_id: Uuid,
    /// Device ID (v2 only, None for v1 invites)
    pub device_id: Option<String>,
    pub ephemeral_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn test_canonical_string_v1() {
        let invite = InviteToken {
            v: 1,
            jti: Uuid::parse_str("25a5e378-c873-4e4b-a16a-a8d299386d3d").unwrap(),
            uuid: Uuid::parse_str("af70cf9a-b176-4df3-b6bf-00196a6f173e").unwrap(),
            device_id: None,
            server: "konstruct.cc".to_string(),
            eph_key: "test_key_base64".to_string(),
            ts: 1675209600,
            sig: "test_sig".to_string(),
        };

        let canonical = invite.canonical_string();
        assert_eq!(
            canonical,
            "1|25a5e378-c873-4e4b-a16a-a8d299386d3d|af70cf9a-b176-4df3-b6bf-00196a6f173e|konstruct.cc|test_key_base64|1675209600"
        );
    }

    #[test]
    fn test_canonical_string_v2() {
        let invite = InviteToken {
            v: 2,
            jti: Uuid::parse_str("25a5e378-c873-4e4b-a16a-a8d299386d3d").unwrap(),
            uuid: Uuid::parse_str("af70cf9a-b176-4df3-b6bf-00196a6f173e").unwrap(),
            device_id: Some("4e1f9dbe209c1bedb33ee32dda5a28f0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: "test_key_base64".to_string(),
            ts: 1675209600,
            sig: "test_sig".to_string(),
        };

        let canonical = invite.canonical_string();
        assert_eq!(
            canonical,
            "2|25a5e378-c873-4e4b-a16a-a8d299386d3d|af70cf9a-b176-4df3-b6bf-00196a6f173e|4e1f9dbe209c1bedb33ee32dda5a28f0|konstruct.cc|test_key_base64|1675209600"
        );
    }

    #[test]
    fn test_is_expired() {
        let old_invite = InviteToken {
            v: 1,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None,
            server: "test.com".to_string(),
            eph_key: "key".to_string(),
            ts: Utc::now().timestamp() - 400, // 400 seconds ago
            sig: "sig".to_string(),
        };

        assert!(old_invite.is_expired(300)); // 5 min TTL
        assert!(!old_invite.is_expired(500)); // 8.3 min TTL
    }

    #[test]
    fn test_is_future() {
        let future_invite = InviteToken {
            v: 1,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None,
            server: "test.com".to_string(),
            eph_key: "key".to_string(),
            ts: Utc::now().timestamp() + 200, // 200 seconds in future
            sig: "sig".to_string(),
        };

        assert!(future_invite.is_future());
    }

    #[test]
    fn test_validate_v1_success() {
        let invite = InviteToken {
            v: 1,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None,
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
        };

        assert!(invite.validate().is_ok());
    }

    #[test]
    fn test_validate_v2_success() {
        let invite = InviteToken {
            v: 2,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: Some("4e1f9dbe209c1bedb33ee32dda5a28f0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
        };

        assert!(invite.validate().is_ok());
    }

    #[test]
    fn test_validate_v2_missing_device_id() {
        let invite = InviteToken {
            v: 2,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None, // Missing!
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::MissingDeviceID)
        ));
    }

    #[test]
    fn test_validate_invalid_device_id_length() {
        let invite = InviteToken {
            v: 2,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: Some("tooshort".to_string()), // Wrong length!
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::InvalidDeviceID)
        ));
    }

    #[test]
    fn test_validate_invalid_device_id_uppercase() {
        let invite = InviteToken {
            v: 2,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: Some("4E1F9DBE209C1BEDB33EE32DDA5A28F0".to_string()), // Uppercase!
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::InvalidDeviceID)
        ));
    }

    #[test]
    fn test_validate_unsupported_version() {
        let invite = InviteToken {
            v: 99,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None,
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::UnsupportedVersion(99))
        ));
    }
}
