// ============================================================================
// construct-user-service
// ============================================================================
//
// User service business logic: account management, key operations,
// invite system, and account deletion.
// Extracted from shared/ for reuse across the monolith and the
// user-service microservice binary.
//
// ============================================================================

pub mod account;
pub mod account_deletion;
pub mod context;
pub mod core;
pub mod invites;

pub use context::UserServiceContext;
