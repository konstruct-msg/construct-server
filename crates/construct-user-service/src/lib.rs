// ============================================================================
// construct-user-service
// ============================================================================
//
// Non-HTTP business helpers for user account metadata.
// Invite / account-deletion product paths live in identity-service gRPC
// (`invite_core`, UserService.DeleteAccount). REST wrappers removed.
//
// ============================================================================

pub mod context;
pub mod core;

pub use context::UserServiceContext;
