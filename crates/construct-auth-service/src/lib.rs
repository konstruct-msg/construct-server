// ============================================================================
// construct-auth-service
// ============================================================================
//
// Auth service business logic: device registration, authentication,
// token refresh, and logout. Extracted from shared/ for reuse across
// the monolith and the auth-service microservice binary.
//
// ============================================================================

pub mod core;
pub mod devices;
