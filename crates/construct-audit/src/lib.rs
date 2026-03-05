// ============================================================================
// Audit Logging - Security-Critical Operations
// ============================================================================
//
// Provides structured audit logging for security-critical operations:
// - Login/logout events
// - Password changes
// - Key rotations
// - Account deletions
// - Admin actions (if any)
//
// Audit logs are:
// - Immutable (append-only)
// - Structured (JSON for SIEM integration)
// - Privacy-preserving (hashed identifiers)
// - Comprehensive (all security events)
//
// ============================================================================

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    /// User login attempt (successful or failed)
    LoginAttempt,
    /// User logout
    Logout,
    /// Password change
    PasswordChange,
    /// Key bundle rotation/update
    KeyRotation,
    /// Account deletion
    AccountDeletion,
    /// Failed authentication attempt (for brute force detection)
    AuthenticationFailure,
    /// Session revocation (e.g., after password change)
    SessionRevocation,
    /// Rate limit violation
    RateLimitViolation,
    /// Security violation (e.g., spoofing attempt)
    SecurityViolation,
}

/// Audit event for security-critical operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp (ISO8601)
    pub timestamp: String,

    /// Event type
    #[serde(rename = "event_type")]
    pub event_type: AuditEventType,

    /// User ID (hashed for privacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id_hash: Option<String>,

    /// Username (hashed for privacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_hash: Option<String>,

    /// Client IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,

    /// Success status (true = success, false = failure)
    pub success: bool,

    /// Additional context/error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Session ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event
    pub fn new(
        event_type: AuditEventType,
        user_id_hash: Option<String>,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        success: bool,
        details: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            user_id_hash,
            username_hash,
            client_ip,
            success,
            details,
            session_id,
        }
    }

    /// Serializes audit event to JSON for logging
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Audit logger for security-critical operations
pub struct AuditLogger;

impl AuditLogger {
    /// Logs a login attempt (successful or failed)
    pub fn log_login_attempt(
        user_id_hash: Option<String>,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        success: bool,
        details: Option<String>,
        session_id: Option<String>,
    ) {
        let event = AuditEvent::new(
            AuditEventType::LoginAttempt,
            user_id_hash,
            username_hash,
            client_ip,
            success,
            details,
            session_id,
        );

        Self::log_event(&event);
    }

    /// Logs a logout event
    pub fn log_logout(
        user_id_hash: Option<String>,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        session_id: Option<String>,
    ) {
        let event = AuditEvent::new(
            AuditEventType::Logout,
            user_id_hash,
            username_hash,
            client_ip,
            true, // Logout is always successful if executed
            None,
            session_id,
        );

        Self::log_event(&event);
    }

    /// Logs a password change event
    pub fn log_password_change(
        user_id_hash: String,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        success: bool,
        details: Option<String>,
        session_id: Option<String>,
    ) {
        let event = AuditEvent::new(
            AuditEventType::PasswordChange,
            Some(user_id_hash),
            username_hash,
            client_ip,
            success,
            details,
            session_id,
        );

        Self::log_event(&event);
    }

    /// Logs a key rotation event
    pub fn log_key_rotation(
        user_id_hash: String,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        success: bool,
        details: Option<String>,
    ) {
        let event = AuditEvent::new(
            AuditEventType::KeyRotation,
            Some(user_id_hash),
            username_hash,
            client_ip,
            success,
            details,
            None, // Key rotation doesn't involve sessions
        );

        Self::log_event(&event);
    }

    /// Logs an account deletion event
    pub fn log_account_deletion(
        user_id_hash: String,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        success: bool,
        details: Option<String>,
    ) {
        let event = AuditEvent::new(
            AuditEventType::AccountDeletion,
            Some(user_id_hash),
            username_hash,
            client_ip,
            success,
            details,
            None, // Account deletion revokes all sessions
        );

        Self::log_event(&event);
    }

    /// Logs an authentication failure (for brute force detection)
    pub fn log_authentication_failure(
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        details: Option<String>,
    ) {
        let event = AuditEvent::new(
            AuditEventType::AuthenticationFailure,
            None, // No user_id for failed auth
            username_hash,
            client_ip,
            false,
            details,
            None,
        );

        Self::log_event(&event);
    }

    /// Logs session revocation (e.g., after password change)
    pub fn log_session_revocation(
        user_id_hash: String,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        reason: String,
    ) {
        let event = AuditEvent::new(
            AuditEventType::SessionRevocation,
            Some(user_id_hash),
            username_hash,
            client_ip,
            true,
            Some(reason),
            None, // All sessions revoked
        );

        Self::log_event(&event);
    }

    /// Logs a rate limit violation
    pub fn log_rate_limit_violation(
        user_id_hash: Option<String>,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        limit_type: String,
        count: u32,
        limit: u32,
    ) {
        let details = format!(
            "Rate limit exceeded: {} (count={}, limit={})",
            limit_type, count, limit
        );
        let event = AuditEvent::new(
            AuditEventType::RateLimitViolation,
            user_id_hash,
            username_hash,
            client_ip,
            false,
            Some(details),
            None,
        );

        Self::log_event(&event);
    }

    /// Logs a security violation (e.g., spoofing attempt)
    pub fn log_security_violation(
        user_id_hash: Option<String>,
        username_hash: Option<String>,
        client_ip: Option<IpAddr>,
        violation_type: String,
        details: Option<String>,
    ) {
        let full_details = format!("Security violation: {}", violation_type);
        let event = AuditEvent::new(
            AuditEventType::SecurityViolation,
            user_id_hash,
            username_hash,
            client_ip,
            false,
            details.or(Some(full_details)),
            None,
        );

        Self::log_event(&event);
    }

    /// Internal function to actually log the audit event
    ///
    /// Uses tracing with structured logging at INFO level
    /// The event is serialized to JSON for SIEM integration
    fn log_event(event: &AuditEvent) {
        let json = event.to_json();

        // Log at INFO level with structured fields
        // This allows log aggregation systems to parse and index audit events
        tracing::info!(
            target: "audit",
            event_type = ?event.event_type,
            user_id_hash = event.user_id_hash.as_deref(),
            username_hash = event.username_hash.as_deref(),
            client_ip = ?event.client_ip,
            success = event.success,
            details = event.details.as_deref(),
            session_id = event.session_id.as_deref(),
            timestamp = %event.timestamp,
            json = %json,
            "AUDIT: Security event logged"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(
            AuditEventType::LoginAttempt,
            Some("abc123".to_string()),
            Some("xyz789".to_string()),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            true,
            Some("Login successful".to_string()),
            Some("session-123".to_string()),
        );

        let json = event.to_json();
        assert!(json.contains("LOGIN_ATTEMPT"));
        assert!(json.contains("abc123"));
        assert!(json.contains("127.0.0.1"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_audit_event_no_optional_fields() {
        let event = AuditEvent::new(
            AuditEventType::AuthenticationFailure,
            None,
            None,
            None,
            false,
            None,
            None,
        );

        let json = event.to_json();
        assert!(json.contains("AUTHENTICATION_FAILURE"));
        assert!(json.contains("false"));
    }
}
