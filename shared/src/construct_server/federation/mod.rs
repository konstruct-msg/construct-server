// ============================================================================
// Federation Module - Cross-Instance Communication
// ============================================================================
//
// Implements S2S (Server-to-Server) federation protocol:
// - Discovery: .well-known/konstruct for endpoint discovery
// - Signing: Ed25519 signatures for S2S authentication
// - Client: Sending messages to remote instances
//
// ============================================================================

pub mod client;
pub mod discovery;
pub mod mtls;
pub mod signing;

pub use client::FederationClient;
pub use discovery::discover_instance;
pub use mtls::{FederationTrustStore, MtlsConfig};
pub use signing::{FederatedEnvelope, PublicKeyCache, ServerSigner, SigningError};
