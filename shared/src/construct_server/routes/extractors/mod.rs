// ============================================================================
// Axum Extractors Module
// ============================================================================
//
// Custom extractors for Axum routes:
// - DeviceAuth: Ed25519 signature-based authentication (passwordless)
// - TrustedUser: Gateway-propagated identity via X-User-Id header
// - OptionalTrustedUser: Optional user (for endpoints that work both ways)
//
// Phase 5.0.1 Gateway Auth Refactoring:
// ✅ COMPLETE - All handlers migrated to TrustedUser
// ❌ AuthenticatedUser removed (deprecated, duplicated JWT verification)
//
// ============================================================================

pub mod device_auth;
pub mod trusted_user;

pub use device_auth::DeviceAuth;
pub use trusted_user::{OptionalTrustedUser, RequestTraceId, TrustedDeviceId, TrustedUser};
