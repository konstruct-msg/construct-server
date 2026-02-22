// ============================================================================
// Dynamic Invite v2 - Server Implementation
// ============================================================================
//
// Supports both v1 (userId only) and v2 (userId + deviceId) invites
// for backwards compatibility during client migration.
//
// Related: INVITE_V2_MIGRATION.md
// ============================================================================

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Dynamic Invite Object (v1/v2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteObject {
    /// Protocol version: 1 or 2
    pub v: u8,

    /// One-time JWT ID (UUIDv4) for tracking
    pub jti: String,

    /// User UUID (for chat creation)
    pub uuid: String,

    /// Device ID (v2 only) - 32-char hex string
    /// None for v1 invites (backwards compat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// Server FQDN (e.g., "konstruct.cc")
    pub server: String,

    /// Ephemeral X25519 public key (Base64)
    #[serde(rename = "ephKey")]
    pub eph_key: String,

    /// Unix timestamp
    pub ts: i64,

    /// Ed25519 signature (Base64, 64 bytes)
    pub sig: String,
}

impl InviteObject {
    /// Get canonical string for signature verification
    ///
    /// Format depends on protocol version:
    /// - v1: `v|jti|uuid|server|ephKey|ts`
    /// - v2: `v|jti|uuid|deviceId|server|ephKey|ts`
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

    /// Validate invite structure (format checks only, not signature)
    pub fn validate(&self) -> Result<(), InviteValidationError> {
        // Version check
        if self.v != 1 && self.v != 2 {
            return Err(InviteValidationError::UnsupportedVersion(self.v));
        }

        // JTI format (UUID)
        if uuid::Uuid::parse_str(&self.jti).is_err() {
            return Err(InviteValidationError::InvalidJTI);
        }

        // User UUID format
        if uuid::Uuid::parse_str(&self.uuid).is_err() {
            return Err(InviteValidationError::InvalidUserUUID);
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
        match STANDARD.decode(&self.eph_key) {
            Ok(bytes) if bytes.len() == 32 => {}
            _ => return Err(InviteValidationError::InvalidEphemeralKey),
        }

        // Timestamp (must be positive, not too far in future)
        let now = chrono::Utc::now().timestamp();
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
}

#[derive(Debug, Error)]
pub enum InviteValidationError {
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

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

    #[error("Invalid ephemeral key (must be Base64, 32 bytes)")]
    InvalidEphemeralKey,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("Invalid signature format")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_string_v1() {
        let invite = InviteObject {
            v: 1,
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            uuid: "650e8400-e29b-41d4-a716-446655440001".to_string(),
            device_id: None,
            server: "konstruct.cc".to_string(),
            eph_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            ts: 1738776000,
            sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        };

        let canonical = invite.canonical_string();
        assert_eq!(
            canonical,
            "1|550e8400-e29b-41d4-a716-446655440000|650e8400-e29b-41d4-a716-446655440001|konstruct.cc|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|1738776000"
        );
    }

    #[test]
    fn test_canonical_string_v2() {
        let invite = InviteObject {
            v: 2,
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            uuid: "650e8400-e29b-41d4-a716-446655440001".to_string(),
            device_id: Some("4e1f9dbe209c1bedb33ee32dda5a28f0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            ts: 1738776000,
            sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        };

        let canonical = invite.canonical_string();
        assert_eq!(
            canonical,
            "2|550e8400-e29b-41d4-a716-446655440000|650e8400-e29b-41d4-a716-446655440001|4e1f9dbe209c1bedb33ee32dda5a28f0|konstruct.cc|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|1738776000"
        );
    }

    #[test]
    fn test_validate_v2_success() {
        let invite = InviteObject {
            v: 2,
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            uuid: "650e8400-e29b-41d4-a716-446655440001".to_string(),
            device_id: Some("4e1f9dbe209c1bedb33ee32dda5a28f0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            ts: chrono::Utc::now().timestamp(),
            sig: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        };

        assert!(invite.validate().is_ok());
    }

    #[test]
    fn test_validate_v2_missing_device_id() {
        let invite = InviteObject {
            v: 2,
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            uuid: "650e8400-e29b-41d4-a716-446655440001".to_string(),
            device_id: None, // Missing!
            server: "konstruct.cc".to_string(),
            eph_key: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            ts: chrono::Utc::now().timestamp(),
            sig: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::MissingDeviceID)
        ));
    }

    #[test]
    fn test_validate_invalid_device_id_length() {
        let invite = InviteObject {
            v: 2,
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            uuid: "650e8400-e29b-41d4-a716-446655440001".to_string(),
            device_id: Some("tooshort".to_string()), // Wrong length!
            server: "konstruct.cc".to_string(),
            eph_key: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            ts: chrono::Utc::now().timestamp(),
            sig: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::InvalidDeviceID)
        ));
    }
}
