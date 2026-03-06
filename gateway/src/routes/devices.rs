// Device registration/auth logic moved to auth_service::devices.
// Re-exported here for backward compatibility with existing HTTP router code.
pub use construct_server_shared::auth_service::devices::*;
