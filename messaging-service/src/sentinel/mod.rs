// Sentinel module re-groups the embedded SentinelService gRPC handler.
// All business logic lives in `construct_server_shared::sentinel_service::core`.

mod grpc;

pub use grpc::SentinelGrpcService;
