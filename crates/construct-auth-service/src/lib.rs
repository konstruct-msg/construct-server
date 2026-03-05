// ============================================================================
// construct-auth-service
// ============================================================================
//
// Auth service business logic: device registration, authentication,
// token refresh, and logout. Extracted from shared/ for reuse across
// the monolith and the auth-service microservice binary.
//
// ============================================================================

pub mod context;
pub mod core;
pub mod devices;

pub use context::AuthServiceContext;
