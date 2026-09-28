// ============================================================================
// Federated User ID Module
// ============================================================================
//
// Supports three formats:
// 1. Local:     "550e8400-e29b-41d4-a716-446655440000" (UUID only)
// 2. Federated: "550e8400-e29b-41d4-a716-446655440000@server.com" (UUID@domain)
// 3. Key address: "ed25519:<64 hex chars>" (identity public key)
//
// This maintains backward compatibility with existing clients while enabling
// federation support.
// ============================================================================

use std::fmt;
use uuid::Uuid;

/// A user address. UUID remains the database key; key addresses resolve through `RouteId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserId {
    Local(Uuid),
    Federated {
        uuid: Uuid,
        domain: String,
    },
    Identity {
        identity_public_key: Vec<u8>,
        route_id: RouteId,
    },
}

impl UserId {
    /// Parse a user ID string into a UserId
    ///
    /// # Formats
    /// - Local: "550e8400-e29b-41d4-a716-446655440000"
    /// - Federated: "550e8400-e29b-41d4-a716-446655440000@server.com"
    /// - Identity: "ed25519:<64 hex chars>" (the public key, not the derived route_id)
    ///
    /// # Examples
    /// ```
    /// use construct_types::UserId;
    ///
    /// let local = UserId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
    /// assert!(local.is_local());
    ///
    /// let federated = UserId::parse("550e8400-e29b-41d4-a716-446655440000@server.com").unwrap();
    /// assert!(!federated.is_local());
    /// ```
    pub fn parse(s: &str) -> Result<Self, UserIdError> {
        if s.is_empty() {
            return Err(UserIdError::Empty);
        }

        if let Some(encoded_key) = s.strip_prefix("ed25519:") {
            let key = hex::decode(encoded_key)
                .map_err(|_| UserIdError::InvalidIdentityKey(encoded_key.to_string()))?;
            if key.len() != 32 {
                return Err(UserIdError::InvalidIdentityKey(encoded_key.to_string()));
            }
            let route_id = RouteId::of_account(&key);
            return Ok(UserId::Identity {
                identity_public_key: key,
                route_id,
            });
        }

        // Check if this is a federated ID (contains @)
        if let Some(at_pos) = s.find('@') {
            // Federated format: uuid@domain
            let uuid_part = &s[..at_pos];
            let domain_part = &s[at_pos + 1..];

            // Validate domain is not empty
            if domain_part.is_empty() {
                return Err(UserIdError::EmptyDomain);
            }

            // Validate domain format (basic validation)
            if !Self::is_valid_domain(domain_part) {
                return Err(UserIdError::InvalidDomain(domain_part.to_string()));
            }

            // Parse UUID part
            let uuid = Uuid::parse_str(uuid_part)
                .map_err(|_| UserIdError::InvalidUuid(uuid_part.to_string()))?;

            Ok(UserId::Federated {
                uuid,
                domain: domain_part.to_string(),
            })
        } else {
            // Local format: just UUID
            let uuid = Uuid::parse_str(s).map_err(|_| UserIdError::InvalidUuid(s.to_string()))?;

            Ok(UserId::Local(uuid))
        }
    }

    /// Check if this is a local user (no domain)
    pub fn is_local(&self) -> bool {
        matches!(self, UserId::Local(_) | UserId::Identity { .. })
    }

    /// Check if this is a federated user
    pub fn is_federated(&self) -> bool {
        matches!(self, UserId::Federated { .. })
    }

    /// Get the domain if this is a federated user
    pub fn domain(&self) -> Option<&str> {
        match self {
            UserId::Federated { domain, .. } => Some(domain),
            _ => None,
        }
    }

    /// Get the UUID part
    pub fn uuid(&self) -> Option<&Uuid> {
        match self {
            UserId::Local(uuid) | UserId::Federated { uuid, .. } => Some(uuid),
            UserId::Identity { .. } => None,
        }
    }

    /// Get the derived route identifier for a key address.
    pub fn route_id(&self) -> Option<&RouteId> {
        match self {
            UserId::Identity { route_id, .. } => Some(route_id),
            _ => None,
        }
    }

    /// Check if this user belongs to a specific domain
    pub fn is_from_domain(&self, domain: &str) -> bool {
        matches!(self, UserId::Federated { domain: d, .. } if d == domain)
    }

    /// Basic domain validation
    /// Checks for:
    /// - Not empty
    /// - Contains at least one dot
    /// - No spaces
    /// - Valid characters (alphanumeric, dash, dot)
    fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        // Must contain at least one dot for valid domain
        if !domain.contains('.') {
            return false;
        }

        // Check for invalid characters
        domain
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserId::Local(uuid) => write!(f, "{uuid}"),
            UserId::Federated { uuid, domain } => write!(f, "{uuid}@{domain}"),
            UserId::Identity {
                identity_public_key,
                ..
            } => write!(f, "ed25519:{}", hex::encode(identity_public_key)),
        }
    }
}

/// Errors that can occur when parsing a user ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIdError {
    Empty,
    EmptyDomain,
    InvalidUuid(String),
    InvalidDomain(String),
    InvalidIdentityKey(String),
}

impl std::fmt::Display for UserIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserIdError::Empty => write!(f, "User ID cannot be empty"),
            UserIdError::EmptyDomain => write!(f, "Domain cannot be empty"),
            UserIdError::InvalidUuid(s) => write!(f, "Invalid UUID format: {}", s),
            UserIdError::InvalidDomain(s) => write!(f, "Invalid domain format: {}", s),
            UserIdError::InvalidIdentityKey(s) => {
                write!(f, "Invalid Ed25519 identity key hex: {}", s)
            }
        }
    }
}

impl std::error::Error for UserIdError {}

// ============================================================================
// RouteId — DHT routing identifier for pubkey-as-identity (Epic E)
// ============================================================================

/// A DHT routing identifier derived from a user's identity public key.
///
/// `route_id = SHA-256(identity_key_type || identity_public_key)`
///
/// The identity_key_type is encoded as a big-endian 2-byte integer before
/// hashing, ensuring that different algorithms produce distinct route_ids
/// and preventing algorithm confusion attacks.
///
/// Displayed as 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteId(String);

/// `identity_key_type` of an Ed25519 key.
pub const IDENTITY_KEY_TYPE_ED25519: i16 = 1;

impl RouteId {
    /// The address of an account: the `route_id` of its **recovery key**
    /// (construct-docs `decisions/pubkey-as-identity.md`, "Which key is the address").
    ///
    /// The recovery key is the one key an account has rather than a device: it survives the loss
    /// of every device and a move to another server, and it cannot change once set
    /// (`check_recovery_key_immutable`), so neither can the address. An `ed25519:<hex>` address
    /// names it; registration and recovery setup store what this computes. One function for all
    /// three, so the three cannot drift apart.
    pub fn of_account(recovery_public_key: &[u8]) -> Self {
        Self::compute(recovery_public_key, IDENTITY_KEY_TYPE_ED25519)
    }

    /// Compute a RouteId from an identity public key and its algorithm type.
    ///
    /// # Algorithm types
    /// - 1 = Ed25519 (32 bytes)
    /// - 2 = ML-DSA-65 (1952 bytes)
    /// - 3 = Hybrid Ed25519+ML-DSA (1984 bytes)
    pub fn compute(identity_public_key: &[u8], identity_key_type: i16) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(identity_key_type.to_be_bytes());
        hasher.update(identity_public_key);
        RouteId(hex::encode(hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RouteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for RouteId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Invalid RouteId: must be 64 hex characters, got '{}'",
                s
            ));
        }
        Ok(RouteId(s.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_user_id() {
        let input = "550e8400-e29b-41d4-a716-446655440000";
        let user_id = UserId::parse(input).unwrap();

        assert!(user_id.is_local());
        assert!(!user_id.is_federated());
        assert_eq!(user_id.domain(), None);
        assert_eq!(user_id.to_string(), input);
    }

    #[test]
    fn test_parse_federated_user_id() {
        let input = "550e8400-e29b-41d4-a716-446655440000@server.com";
        let user_id = UserId::parse(input).unwrap();

        assert!(!user_id.is_local());
        assert!(user_id.is_federated());
        assert_eq!(user_id.domain(), Some("server.com"));
        assert_eq!(user_id.to_string(), input);
    }

    #[test]
    fn test_parse_federated_subdomain() {
        let input = "550e8400-e29b-41d4-a716-446655440000@mail.example.com";
        let user_id = UserId::parse(input).unwrap();

        assert!(user_id.is_federated());
        assert_eq!(user_id.domain(), Some("mail.example.com"));
    }

    #[test]
    fn test_parse_empty_string() {
        let result = UserId::parse("");
        assert!(matches!(result, Err(UserIdError::Empty)));
    }

    #[test]
    fn test_parse_invalid_uuid() {
        let result = UserId::parse("not-a-uuid");
        assert!(matches!(result, Err(UserIdError::InvalidUuid(_))));
    }

    #[test]
    fn test_parse_invalid_federated_uuid() {
        let result = UserId::parse("not-a-uuid@server.com");
        assert!(matches!(result, Err(UserIdError::InvalidUuid(_))));
    }

    #[test]
    fn test_parse_empty_domain() {
        let result = UserId::parse("550e8400-e29b-41d4-a716-446655440000@");
        assert!(matches!(result, Err(UserIdError::EmptyDomain)));
    }

    #[test]
    fn test_parse_invalid_domain_no_dot() {
        let result = UserId::parse("550e8400-e29b-41d4-a716-446655440000@localhost");
        assert!(matches!(result, Err(UserIdError::InvalidDomain(_))));
    }

    #[test]
    fn test_parse_invalid_domain_with_spaces() {
        let result = UserId::parse("550e8400-e29b-41d4-a716-446655440000@server .com");
        assert!(matches!(result, Err(UserIdError::InvalidDomain(_))));
    }

    #[test]
    fn test_is_from_domain() {
        let local = UserId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert!(!local.is_from_domain("server.com"));

        let federated = UserId::parse("550e8400-e29b-41d4-a716-446655440000@server.com").unwrap();
        assert!(federated.is_from_domain("server.com"));
        assert!(!federated.is_from_domain("other.com"));
    }

    /// Known answer computed outside this crate (Python `hashlib`): `SHA-256(0x0001 || key)`.
    /// The address a client derives and the route_id the server stored must be the same bytes.
    #[test]
    fn a_key_address_names_the_accounts_route_id() {
        let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let address = UserId::parse(&format!("ed25519:{key_hex}")).unwrap();
        let expected = "a1ad370bf8dfbc15b16ad2f83aeab93c34c4bbc62577d87ac9d1ac5334e4c603";
        assert_eq!(address.route_id().unwrap().as_str(), expected);
        assert_eq!(
            RouteId::of_account(&hex::decode(key_hex).unwrap()).as_str(),
            expected
        );
        assert!(
            address.uuid().is_none(),
            "a key address has no UUID until resolved"
        );
        assert!(address.is_local() && !address.is_federated());
        assert_eq!(address.to_string(), format!("ed25519:{key_hex}"));
        let upper = UserId::parse(&format!("ed25519:{}", key_hex.to_uppercase())).unwrap();
        assert_eq!(
            upper.route_id(),
            address.route_id(),
            "hex case does not change the address"
        );
    }

    #[test]
    fn a_key_address_that_is_not_32_bytes_of_hex_is_refused() {
        for bad in [
            "ed25519:",
            "ed25519:zz",
            "ed25519:0001",
            &format!("ed25519:{}", "00".repeat(33)),
        ] {
            assert!(
                matches!(UserId::parse(bad), Err(UserIdError::InvalidIdentityKey(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_uuid_extraction() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let expected_uuid = Uuid::parse_str(uuid_str).unwrap();

        let local = UserId::parse(uuid_str).unwrap();
        assert_eq!(*local.uuid().unwrap(), expected_uuid);

        let federated = UserId::parse(&format!("{}@server.com", uuid_str)).unwrap();
        assert_eq!(*federated.uuid().unwrap(), expected_uuid);
    }
}
