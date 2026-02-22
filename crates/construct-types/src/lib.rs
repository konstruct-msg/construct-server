// ============================================================================
// Construct Types - Core Data Types
// ============================================================================
//
// This crate contains all core data structures used across the Construct
// messaging platform. It has NO dependencies on business logic, databases,
// or external services.
//
// Contents:
// - User identifiers (local and federated)
// - Message types (client/server protocol)
// - Key bundle structures (will be moved here from e2e.rs)
// - Request/Response data structures
//
// Dependencies:
// - serde (serialization only)
// - uuid (identifiers)
// - chrono (timestamps)
//
// ============================================================================

pub mod message;
pub mod user_id;

// Re-exports for convenience
pub use message::*;
pub use user_id::*;
