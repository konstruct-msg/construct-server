// ============================================================================
// Federated User ID Module
// ============================================================================
//
// Supports two formats:
// 1. Local:     "550e8400-e29b-41d4-a716-446655440000" (UUID only)
// 2. Federated: "550e8400-e29b-41d4-a716-446655440000@server.com" (UUID@domain)
//
// This maintains backward compatibility with existing clients while enabling
// federation support.
// ============================================================================

use std::fmt;
use uuid::Uuid;

/// Represents a user ID that can be either local or federated
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId {
    /// The UUID part of the user ID
    pub uuid: Uuid,
    /// The domain part (None for local users)
    pub domain: Option<String>,
}

impl UserId {
    /// Parse a user ID string into a UserId
    ///
    /// # Formats
    /// - Local: "550e8400-e29b-41d4-a716-446655440000"
    /// - Federated: "550e8400-e29b-41d4-a716-446655440000@server.com"
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

            Ok(UserId {
                uuid,
                domain: Some(domain_part.to_string()),
            })
        } else {
            // Local format: just UUID
            let uuid = Uuid::parse_str(s).map_err(|_| UserIdError::InvalidUuid(s.to_string()))?;

            Ok(UserId { uuid, domain: None })
        }
    }

    /// Check if this is a local user (no domain)
    pub fn is_local(&self) -> bool {
        self.domain.is_none()
    }

    /// Check if this is a federated user
    pub fn is_federated(&self) -> bool {
        self.domain.is_some()
    }

    /// Get the domain if this is a federated user
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Get the UUID part
    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    /// Check if this user belongs to a specific domain
    pub fn is_from_domain(&self, domain: &str) -> bool {
        match &self.domain {
            Some(d) => d == domain,
            None => false,
        }
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
        match &self.domain {
            Some(domain) => write!(f, "{}@{}", self.uuid, domain),
            None => write!(f, "{}", self.uuid),
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
}

impl std::fmt::Display for UserIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserIdError::Empty => write!(f, "User ID cannot be empty"),
            UserIdError::EmptyDomain => write!(f, "Domain cannot be empty"),
            UserIdError::InvalidUuid(s) => write!(f, "Invalid UUID format: {}", s),
            UserIdError::InvalidDomain(s) => write!(f, "Invalid domain format: {}", s),
        }
    }
}

impl std::error::Error for UserIdError {}

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

    #[test]
    fn test_uuid_extraction() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let expected_uuid = Uuid::parse_str(uuid_str).unwrap();

        let local = UserId::parse(uuid_str).unwrap();
        assert_eq!(*local.uuid(), expected_uuid);

        let federated = UserId::parse(&format!("{}@server.com", uuid_str)).unwrap();
        assert_eq!(*federated.uuid(), expected_uuid);
    }
}
