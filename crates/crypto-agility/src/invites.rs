use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Server maximum redeemable age for a signed invite, in seconds.
///
/// Carriers (must stay in agreement — see INVITE_LIST_REVOKE_SERVER_SPEC):
///   1. here — ceiling used by `effective_ttl()` / accept path;
///   2. `used_invites` burn retention (`INVITE_BURN_RETENTION_SECONDS`);
///   3. client link mint (iOS `InviteConfig.ttlSeconds` for copy-link = this value).
///
/// v5 invites may request a *shorter* life via signed `ttl` (QR = 300 s); they
/// cannot exceed this ceiling. Burn retention always uses this max, not the
/// per-invite value.
///
/// 2026-08-13: 300 → 43200 (12h) so links survive another messenger's inbox.
/// QR no longer inherits that window — see v5 `ttl` field.
pub const INVITE_TTL_SECONDS: i64 = 43_200;

/// Hard floor for v5 `ttl` (seconds). Product QR target is 300; below 60 is noise.
pub const INVITE_TTL_MIN_SECONDS: u32 = 60;

/// How long a burn record must outlive the accept/revoke that wrote it.
///
/// Derived from the **maximum** invite life only — never from a per-token `ttl`.
/// The extra hour absorbs clock skew between machines.
pub const INVITE_BURN_RETENTION_SECONDS: i64 = INVITE_TTL_SECONDS + 3_600;

/// Invite token object for one-time contact sharing (v1–v5)
///
/// Cryptographically signed by the user's Identity Key; QR / deep link encoded.
///
/// Protocol versions:
/// - v1: userId only (backwards compatible)
/// - v2: userId + deviceId
/// - v3: userId + deviceId + username
/// - v4: userId + deviceId + username, **no ephKey** (pure signed capability)
/// - v5: v4 + signed client `ttl` (server effective = min(INVITE_TTL_SECONDS, ttl))
///
/// Security properties:
/// - One-time use (jti burn)
/// - Bounded TTL (server max; v5 may only shorten)
/// - Ed25519 authenticity over the canonical string
/// - Federation-ready (server FQDN)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteToken {
    /// Protocol version: 1–5
    pub v: u32,

    /// Unique invite ID (JWT jti) - prevents replay attacks
    pub jti: Uuid,

    /// User UUID who created this invite
    pub uuid: Uuid,

    /// Device ID (v2+) - 32-char lowercase hex string
    /// None for v1 invites (backwards compat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// Server FQDN (e.g., "konstruct.cc") for federation
    pub server: String,

    /// Ephemeral X25519 public key (Base64 encoded) — **v1–v3 only**.
    /// Empty string on v4+ (field dropped from canonical string).
    #[serde(default)]
    pub eph_key: String,

    /// Unix timestamp when this invite was created
    pub ts: i64,

    /// Ed25519 signature over canonical form
    /// v1: (v, jti, uuid, server, ephKey, ts)
    /// v2: (v, jti, uuid, deviceId, server, ephKey, ts)
    /// v3: (v, jti, uuid, deviceId, server, ephKey, ts, username)
    /// v4: (v, jti, uuid, deviceId, server, ts, username)
    /// v5: (v, jti, uuid, deviceId, server, ts, username, ttl)
    /// Signed with user's long-term Identity Key
    pub sig: String,

    /// Username of the sender (v3+) - for display purposes
    /// Empty string if not set. Signed as part of canonical string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Client-stated maximum age in seconds (**v5 required**).
    /// Covered by the signature. Server uses `min(INVITE_TTL_SECONDS, ttl)`.
    /// Absent on v1–v4 → effective TTL is `INVITE_TTL_SECONDS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
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

    #[error("Missing ttl for v5 invite")]
    MissingTtl,

    #[error("Invalid ttl (must be non-zero and >= 60 seconds)")]
    InvalidTtl,
}

impl InviteToken {
    /// Create canonical string for signature verification.
    ///
    /// Format depends on protocol version:
    /// - v1: `v|jti|uuid|server|ephKey|ts`
    /// - v2: `v|jti|uuid|deviceId|server|ephKey|ts`
    /// - v3: `v|jti|uuid|deviceId|server|ephKey|ts|username`
    /// - v4: `v|jti|uuid|deviceId|server|ts|username` (no ephKey)
    /// - v5: `v|jti|uuid|deviceId|server|ts|username|ttl`
    ///
    /// Unknown versions return `UnsupportedVersion` (never fall through to v4).
    /// Must match iOS `InviteObject.canonicalString` / Android — including that
    /// iOS must use explicit `case 4` / `case 5`, not `default` = v4 shape.
    pub fn canonical_string(&self) -> Result<String, InviteValidationError> {
        match self.v {
            1 => Ok(format!(
                "{}|{}|{}|{}|{}|{}",
                self.v, self.jti, self.uuid, self.server, self.eph_key, self.ts
            )),
            2 => {
                let device_id = self
                    .device_id
                    .as_ref()
                    .ok_or(InviteValidationError::MissingDeviceID)?;
                Ok(format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    self.v, self.jti, self.uuid, device_id, self.server, self.eph_key, self.ts
                ))
            }
            3 => {
                let device_id = self
                    .device_id
                    .as_ref()
                    .ok_or(InviteValidationError::MissingDeviceID)?;
                let username = self.username.as_deref().unwrap_or("");
                Ok(format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}",
                    self.v,
                    self.jti,
                    self.uuid,
                    device_id,
                    self.server,
                    self.eph_key,
                    self.ts,
                    username
                ))
            }
            4 => {
                let device_id = self
                    .device_id
                    .as_ref()
                    .ok_or(InviteValidationError::MissingDeviceID)?;
                let username = self.username.as_deref().unwrap_or("");
                Ok(format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    self.v, self.jti, self.uuid, device_id, self.server, self.ts, username
                ))
            }
            5 => {
                let device_id = self
                    .device_id
                    .as_ref()
                    .ok_or(InviteValidationError::MissingDeviceID)?;
                let username = self.username.as_deref().unwrap_or("");
                let ttl = self.ttl.ok_or(InviteValidationError::MissingTtl)?;
                // Decimal integer as rendered (e.g. "300") — part of the protocol.
                Ok(format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}",
                    self.v, self.jti, self.uuid, device_id, self.server, self.ts, username, ttl
                ))
            }
            other => Err(InviteValidationError::UnsupportedVersion(other)),
        }
    }

    /// Effective redeem window in seconds: `min(INVITE_TTL_SECONDS, token.ttl)` for v5;
    /// `INVITE_TTL_SECONDS` for v1–v4.
    pub fn effective_ttl(&self) -> Result<i64, InviteValidationError> {
        match self.v {
            1..=4 => Ok(INVITE_TTL_SECONDS),
            5 => {
                let ttl = self.ttl.ok_or(InviteValidationError::MissingTtl)?;
                if ttl == 0 || ttl < INVITE_TTL_MIN_SECONDS {
                    return Err(InviteValidationError::InvalidTtl);
                }
                Ok(INVITE_TTL_SECONDS.min(ttl as i64))
            }
            other => Err(InviteValidationError::UnsupportedVersion(other)),
        }
    }

    /// Whether `now - ts` exceeds `ttl_seconds`.
    ///
    /// Callers should pass [`Self::effective_ttl`] (or the server max for legacy paths).
    /// There is no single default TTL for all invite artifacts: links use
    /// [`INVITE_TTL_SECONDS`] (12 h); v5 QR mints typically use 300 s.
    pub fn is_expired(&self, ttl_seconds: i64) -> bool {
        let now = Utc::now().timestamp();
        (now - self.ts) > ttl_seconds
    }

    /// Check if timestamp is in the future (clock skew attack)
    pub fn is_future(&self) -> bool {
        let now = Utc::now().timestamp();
        self.ts > (now + 60) // Allow 60s clock skew
    }

    /// Validate invite structure (format checks only, not signature).
    pub fn validate(&self) -> Result<(), InviteValidationError> {
        if !matches!(self.v, 1..=5) {
            return Err(InviteValidationError::UnsupportedVersion(self.v));
        }

        // Device ID validation (required for v2+)
        if self.v >= 2 {
            match &self.device_id {
                None => return Err(InviteValidationError::MissingDeviceID),
                Some(device_id) => {
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

        if self.server.is_empty() || !self.server.contains('.') {
            return Err(InviteValidationError::InvalidServer);
        }

        use base64::{Engine as _, engine::general_purpose::STANDARD};

        // Ephemeral key: required (32B) for v1–v3; must be empty for v4+
        if self.v <= 3 {
            match STANDARD.decode(&self.eph_key) {
                Ok(bytes) if bytes.len() == 32 => {}
                _ => return Err(InviteValidationError::InvalidEphemeralKey),
            }
        } else if !self.eph_key.is_empty() {
            return Err(InviteValidationError::InvalidEphemeralKey);
        }

        // v5: ttl required, non-zero, >= floor (overshoot clamped later in effective_ttl)
        if self.v == 5 {
            match self.ttl {
                None => return Err(InviteValidationError::MissingTtl),
                Some(0) => return Err(InviteValidationError::InvalidTtl),
                Some(t) if t < INVITE_TTL_MIN_SECONDS => {
                    return Err(InviteValidationError::InvalidTtl);
                }
                Some(_) => {}
            }
        }

        let now = Utc::now().timestamp();
        if self.ts <= 0 || self.ts > now + 300 {
            return Err(InviteValidationError::InvalidTimestamp);
        }

        match STANDARD.decode(&self.sig) {
            Ok(bytes) if bytes.len() == 64 => {}
            _ => return Err(InviteValidationError::InvalidSignature),
        }

        Ok(())
    }

    /// Full validation including expiry using [`Self::effective_ttl`].
    pub fn validate_with_expiry(&self) -> Result<(), InviteValidationError> {
        self.validate()?;

        let ttl_seconds = self.effective_ttl()?;

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
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn sample_v4(ts: i64) -> InviteToken {
        InviteToken {
            v: 4,
            jti: Uuid::nil(),
            uuid: Uuid::nil(),
            device_id: Some("4e1f9dbe209c1bedb33ee32dda5a28f0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: String::new(),
            ts,
            sig: STANDARD.encode([0u8; 64]),
            username: Some("alice".to_string()),
            ttl: None,
        }
    }

    fn sample_v5(ts: i64, ttl: Option<u32>) -> InviteToken {
        InviteToken {
            v: 5,
            jti: Uuid::nil(),
            uuid: Uuid::nil(),
            device_id: Some("4e1f9dbe209c1bedb33ee32dda5a28f0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: String::new(),
            ts,
            sig: STANDARD.encode([0u8; 64]),
            username: Some("alice".to_string()),
            ttl,
        }
    }

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
            username: None,
            ttl: None,
        };

        let canonical = invite.canonical_string().unwrap();
        assert_eq!(
            canonical,
            "1|25a5e378-c873-4e4b-a16a-a8d299386d3d|af70cf9a-b176-4df3-b6bf-00196a6f173e|konstruct.cc|test_key_base64|1675209600"
        );
    }

    #[test]
    fn test_canonical_string_v4_no_eph() {
        let invite = sample_v4(1_738_156_800);
        let canonical = invite.canonical_string().unwrap();
        assert_eq!(
            canonical,
            "4|00000000-0000-0000-0000-000000000000|00000000-0000-0000-0000-000000000000|4e1f9dbe209c1bedb33ee32dda5a28f0|konstruct.cc|1738156800|alice"
        );
        assert!(invite.validate().is_ok());
    }

    #[test]
    fn test_canonical_string_v5_appends_ttl() {
        let invite = sample_v5(1_738_156_800, Some(300));
        let canonical = invite.canonical_string().unwrap();
        assert_eq!(
            canonical,
            "5|00000000-0000-0000-0000-000000000000|00000000-0000-0000-0000-000000000000|4e1f9dbe209c1bedb33ee32dda5a28f0|konstruct.cc|1738156800|alice|300"
        );
        assert!(invite.validate().is_ok());
        assert_eq!(invite.effective_ttl().unwrap(), 300);
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
            username: None,
            ttl: None,
        };

        let canonical = invite.canonical_string().unwrap();
        assert_eq!(
            canonical,
            "2|25a5e378-c873-4e4b-a16a-a8d299386d3d|af70cf9a-b176-4df3-b6bf-00196a6f173e|4e1f9dbe209c1bedb33ee32dda5a28f0|konstruct.cc|test_key_base64|1675209600"
        );
    }

    #[test]
    fn test_canonical_string_unsupported_version_is_err() {
        let invite = InviteToken {
            v: 99,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None,
            server: "konstruct.cc".to_string(),
            eph_key: String::new(),
            ts: Utc::now().timestamp(),
            sig: String::new(),
            username: None,
            ttl: None,
        };
        assert!(matches!(
            invite.canonical_string(),
            Err(InviteValidationError::UnsupportedVersion(99))
        ));
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
            ts: Utc::now().timestamp() - 400,
            sig: "sig".to_string(),
            username: None,
            ttl: None,
        };

        assert!(old_invite.is_expired(300));
        assert!(!old_invite.is_expired(500));
    }

    #[test]
    fn test_v5_short_ttl_expires_while_max_would_not() {
        let invite = sample_v5(Utc::now().timestamp() - 400, Some(300));
        assert!(invite.is_expired(invite.effective_ttl().unwrap()));
        assert!(!invite.is_expired(INVITE_TTL_SECONDS));
        assert!(matches!(
            invite.validate_with_expiry(),
            Err(InviteValidationError::Expired)
        ));
    }

    #[test]
    fn test_v5_overshoot_clamped_to_server_max() {
        let invite = sample_v5(Utc::now().timestamp(), Some(100_000));
        assert_eq!(invite.effective_ttl().unwrap(), INVITE_TTL_SECONDS);
        assert!(invite.validate_with_expiry().is_ok());
    }

    #[test]
    fn test_v5_ttl_zero_and_below_floor() {
        assert!(matches!(
            sample_v5(Utc::now().timestamp(), Some(0)).validate(),
            Err(InviteValidationError::InvalidTtl)
        ));
        assert!(matches!(
            sample_v5(Utc::now().timestamp(), Some(59)).validate(),
            Err(InviteValidationError::InvalidTtl)
        ));
        assert!(matches!(
            sample_v5(Utc::now().timestamp(), None).validate(),
            Err(InviteValidationError::MissingTtl)
        ));
    }

    #[test]
    fn test_v4_still_uses_server_max_ttl() {
        let invite = sample_v4(Utc::now().timestamp());
        assert_eq!(invite.effective_ttl().unwrap(), INVITE_TTL_SECONDS);
        assert!(invite.validate_with_expiry().is_ok());
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
            ts: Utc::now().timestamp() + 200,
            sig: "sig".to_string(),
            username: None,
            ttl: None,
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
            username: None,
            ttl: None,
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
            username: None,
            ttl: None,
        };

        assert!(invite.validate().is_ok());
    }

    #[test]
    fn test_validate_v2_missing_device_id() {
        let invite = InviteToken {
            v: 2,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            device_id: None,
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
            username: None,
            ttl: None,
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
            device_id: Some("tooshort".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
            username: None,
            ttl: None,
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
            device_id: Some("4E1F9DBE209C1BEDB33EE32DDA5A28F0".to_string()),
            server: "konstruct.cc".to_string(),
            eph_key: STANDARD.encode([0u8; 32]),
            ts: Utc::now().timestamp(),
            sig: STANDARD.encode([0u8; 64]),
            username: None,
            ttl: None,
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
            username: None,
            ttl: None,
        };

        assert!(matches!(
            invite.validate(),
            Err(InviteValidationError::UnsupportedVersion(99))
        ));
    }
}
