// Request signing logic moved to construct-utils::request_signing
// Re-exported here for backward compatibility with existing code.

pub use construct_types::api::RequestSignature;
pub use construct_utils::request_signing::{
    RequestSigningError, compute_body_hash, create_canonical_request_bytes,
    extract_request_signature, verify_request_signature,
};
