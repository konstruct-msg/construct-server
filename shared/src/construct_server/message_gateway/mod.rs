// ============================================================================
// Message Gateway - Central Message Processing Service
// ============================================================================
//
// The Message Gateway Service handles all message validation, rate limiting,
// and routing decisions. It acts as the central hub for both local and
// federated message delivery.
//
// Architecture:
// - Stateless processing (can scale horizontally)
// - gRPC API for message submission
// - Kafka producer for validated messages
// - Foundation for future federation support
//
// Responsibilities:
// 1. Message validation (structure, signatures, E2E envelope)
// 2. Rate limiting and user blocking
// 3. Anti-spoofing checks (sender verification)
// 4. Replay protection (deduplication)
// 5. Routing decisions (local vs remote - future)
// 6. Kafka message production
//
// Future: Federation routing (local vs remote nodes)
// ============================================================================

pub mod client;
pub mod grpc;
pub mod rate_limiter;
pub mod router;
pub mod validator;

pub use client::MessageGatewayClient;
pub use rate_limiter::RateLimiter;
pub use router::MessageRouter;
pub use validator::MessageValidator;
