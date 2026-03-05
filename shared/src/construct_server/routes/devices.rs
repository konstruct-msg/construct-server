// Device registration/auth logic moved to auth_service::devices.
// Re-exported here for backward compatibility with existing HTTP router code.
pub use crate::auth_service::devices::*;
