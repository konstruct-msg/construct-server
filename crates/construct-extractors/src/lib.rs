// ============================================================================
// construct-extractors
// ============================================================================
//
// REST Axum extractors (TrustedUser / DeviceAuth) were removed with client REST.
// gRPC services authenticate via `construct_server_shared::auth_utils`
// (Bearer PASETO/JWT + header spoof guards).
//
// This crate remains as a workspace placeholder so historical path deps do not
// break; it intentionally exports nothing.
//
// ============================================================================
