use chrono::{DateTime, Utc};
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

/// The only invite version accepted (since 2026-09-28).
pub const INVITE_VERSION: u32 = 5;

/// Length of `addr`: an Ed25519 public key.
pub const INVITE_ADDR_LEN: usize = 32;

/// A device-minted invite, v5 — the only version.
///
/// v1–v4 were refused from 2026-09-28 (construct-docs
/// `decisions/invite-carries-the-account-address.md`): invites live 5 minutes (QR) or 12 hours
/// (link), there was no installed base of older builds, and nobody had yet minted a v5, so its
/// layout could still change without a v6.
///
/// Security properties:
/// - One-time use (jti burn)
/// - Bounded TTL (server max; `ttl` may only shorten)
/// - Ed25519 authenticity over the canonical string, by the issuing device
/// - `addr` names the issuing account's address (its recovery key) under that signature
#[derive(Debug, Clone)]
pub struct InviteToken {
    /// Protocol version. Only [`INVITE_VERSION`] is accepted.
    pub v: u32,

    /// Unique invite ID (JWT jti) - prevents replay attacks
    pub jti: Uuid,

    /// User UUID who created this invite
    pub uuid: Uuid,

    /// Issuing device — 32-char lowercase hex. Its verifying key checks `sig`.
    pub device_id: String,

    /// Server FQDN (e.g., "konstruct.cc") for federation
    pub server: String,

    /// Unix timestamp when this invite was created
    pub ts: i64,

    /// Ed25519 signature (base64) over [`Self::canonical_string`], by the issuing device.
    pub sig: String,

    /// Username of the sender, for display. Empty when not set. Signed.
    pub username: Option<String>,

    /// Client-stated maximum age in seconds. Signed. Server uses
    /// `min(INVITE_TTL_SECONDS, ttl)`.
    pub ttl: u32,

    /// The issuing account's address: its Ed25519 recovery public key. Signed.
    /// `accept_invite` refuses an invite whose `addr` is not the account's recovery key.
    pub addr: Vec<u8>,
}

/// Validation errors for invite tokens
#[derive(Debug, Error)]
pub enum InviteValidationError {
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("Invalid device ID format (must be 32-char lowercase hex)")]
    InvalidDeviceID,

    #[error("Invalid server FQDN")]
    InvalidServer,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("Invite expired")]
    Expired,

    #[error("Future timestamp (clock skew attack)")]
    FutureTimestamp,

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Invalid ttl (must be >= 60 seconds)")]
    InvalidTtl,

    #[error("Invalid address (must be a 32-byte Ed25519 public key)")]
    InvalidAddress,
}

impl InviteToken {
    /// The signed canonical string: `v|jti|uuid|deviceId|server|ts|username|ttl|hex(addr)`.
    ///
    /// Must match iOS `InviteObject.canonicalString` and Android byte for byte — fixed by
    /// construct-protos `conformance/knst_invite.json`, which `tests::conformance_vector` holds
    /// this function to. UUIDs lowercase hyphenated, `ttl` decimal, `addr` lowercase hex.
    pub fn canonical_string(&self) -> Result<String, InviteValidationError> {
        if self.v != INVITE_VERSION {
            return Err(InviteValidationError::UnsupportedVersion(self.v));
        }
        Ok(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.v,
            self.jti,
            self.uuid,
            self.device_id,
            self.server,
            self.ts,
            self.username.as_deref().unwrap_or(""),
            self.ttl,
            hex::encode(&self.addr)
        ))
    }

    /// Effective redeem window in seconds: `min(INVITE_TTL_SECONDS, ttl)`.
    pub fn effective_ttl(&self) -> i64 {
        INVITE_TTL_SECONDS.min(self.ttl as i64)
    }

    /// Whether `now - ts` exceeds `ttl_seconds`.
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
        if self.v != INVITE_VERSION {
            return Err(InviteValidationError::UnsupportedVersion(self.v));
        }

        if self.device_id.len() != 32
            || !self
                .device_id
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return Err(InviteValidationError::InvalidDeviceID);
        }

        if self.server.is_empty() || !self.server.contains('.') {
            return Err(InviteValidationError::InvalidServer);
        }

        // Overshoot is not an error — `effective_ttl` clamps it.
        if self.ttl < INVITE_TTL_MIN_SECONDS {
            return Err(InviteValidationError::InvalidTtl);
        }

        if self.addr.len() != INVITE_ADDR_LEN {
            return Err(InviteValidationError::InvalidAddress);
        }

        let now = Utc::now().timestamp();
        if self.ts <= 0 || self.ts > now + 300 {
            return Err(InviteValidationError::InvalidTimestamp);
        }

        use base64::{Engine as _, engine::general_purpose::STANDARD};
        match STANDARD.decode(&self.sig) {
            Ok(bytes) if bytes.len() == 64 => {}
            _ => return Err(InviteValidationError::InvalidSignature),
        }

        Ok(())
    }

    /// Full validation including expiry using [`Self::effective_ttl`].
    pub fn validate_with_expiry(&self) -> Result<(), InviteValidationError> {
        self.validate()?;

        if self.is_expired(self.effective_ttl()) {
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

    fn sample(ts: i64, ttl: u32) -> InviteToken {
        InviteToken {
            v: 5,
            jti: Uuid::nil(),
            uuid: Uuid::nil(),
            device_id: "4e1f9dbe209c1bedb33ee32dda5a28f0".to_string(),
            server: "konstruct.cc".to_string(),
            ts,
            sig: STANDARD.encode([0u8; 64]),
            username: Some("alice".to_string()),
            ttl,
            addr: vec![0xab; 32],
        }
    }

    /// construct-protos `conformance/knst_invite.json`, case `with_username`. iOS and Android
    /// build the same string from the same fields; if this reddens, all three disagree about
    /// which bytes are signed, and every invite fails at redeem as "invalid signature".
    #[test]
    fn conformance_vector() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let invite = InviteToken {
            v: 5,
            jti: Uuid::parse_str("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap(),
            uuid: Uuid::parse_str("14f28d31-5b2a-4c1e-9a3d-6f0e2b7c8d90").unwrap(),
            device_id: "6f5e37ac1b2c3d4e5f60718293a4b5c6".to_string(),
            server: "konstruct.cc".to_string(),
            ts: 1_790_000_000,
            sig: String::new(),
            username: Some("alice".to_string()),
            ttl: 300,
            addr: hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap(),
        };
        let canonical = invite.canonical_string().unwrap();
        assert_eq!(
            canonical,
            "5|7c9e6679-7425-40de-944b-e07fc1f90ae7|14f28d31-5b2a-4c1e-9a3d-6f0e2b7c8d90|6f5e37ac1b2c3d4e5f60718293a4b5c6|konstruct.cc|1790000000|alice|300|3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );

        let vk: [u8; 32] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();
        let sig: [u8; 64] = hex::decode(VECTOR_SIGNATURE).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&vk)
            .unwrap()
            .verify(canonical.as_bytes(), &Signature::from_bytes(&sig))
            .expect("the vector's signature verifies over this canonical string");
    }

    const VECTOR_SIGNATURE: &str = "d243215959c9c7bdc3f4f089e678972299f8f1e3f95194217d3c3c197ff39eb967a60043e18f523103717b16cccfeb0ec2ddeea0d91fdee2f81412a781bb9f04";

    /// Mutation: sign without `addr` (drop it from the format) — the address would then ride
    /// unsigned, and anyone relaying the invite could redirect the contact.
    #[test]
    fn the_address_is_signed() {
        let a = sample(1_738_156_800, 300);
        let mut b = a.clone();
        b.addr = vec![0xcd; 32];
        assert_ne!(a.canonical_string().unwrap(), b.canonical_string().unwrap());
    }

    #[test]
    fn only_v5_is_accepted() {
        for v in [1, 2, 3, 4, 6] {
            let mut invite = sample(Utc::now().timestamp(), 300);
            invite.v = v;
            assert!(matches!(
                invite.validate(),
                Err(InviteValidationError::UnsupportedVersion(_))
            ));
            assert!(invite.canonical_string().is_err());
        }
    }

    #[test]
    fn an_address_that_is_not_32_bytes_is_refused() {
        for len in [0, 31, 33] {
            let mut invite = sample(Utc::now().timestamp(), 300);
            invite.addr = vec![1; len];
            assert!(matches!(
                invite.validate(),
                Err(InviteValidationError::InvalidAddress)
            ));
        }
    }

    #[test]
    fn short_ttl_expires_while_max_would_not() {
        let invite = sample(Utc::now().timestamp() - 400, 300);
        assert!(invite.is_expired(invite.effective_ttl()));
        assert!(!invite.is_expired(INVITE_TTL_SECONDS));
        assert!(matches!(
            invite.validate_with_expiry(),
            Err(InviteValidationError::Expired)
        ));
    }

    #[test]
    fn overshoot_is_clamped_to_server_max() {
        let invite = sample(Utc::now().timestamp(), 100_000);
        assert_eq!(invite.effective_ttl(), INVITE_TTL_SECONDS);
        assert!(invite.validate_with_expiry().is_ok());
    }

    #[test]
    fn ttl_below_floor_is_refused() {
        for ttl in [0, 59] {
            assert!(matches!(
                sample(Utc::now().timestamp(), ttl).validate(),
                Err(InviteValidationError::InvalidTtl)
            ));
        }
    }

    #[test]
    fn a_future_timestamp_is_caught() {
        assert!(sample(Utc::now().timestamp() + 200, 300).is_future());
    }

    #[test]
    fn device_id_must_be_lowercase_hex_of_32() {
        for bad in ["tooshort", "4E1F9DBE209C1BEDB33EE32DDA5A28F0"] {
            let mut invite = sample(Utc::now().timestamp(), 300);
            invite.device_id = bad.to_string();
            assert!(matches!(
                invite.validate(),
                Err(InviteValidationError::InvalidDeviceID)
            ));
        }
    }
}
