// ============================================================================
// Key Service - E2EE Key Management
// ============================================================================
//
// Pre-key management service for X3DH key exchange protocol.
// Handles:
// - Pre-key bundles for initiating encrypted sessions
// - One-time pre-key upload and distribution
// - Signed pre-key rotation
// - Identity key verification
//
// Architecture:
// - Stateless handlers (database stores all keys)
// - Server NEVER has access to private keys
// - All keys stored are PUBLIC keys only
//
// ============================================================================

mod core;

use anyhow::{Context, Result};
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    key_service_server::{KeyService, KeyServiceServer},
};

// ============================================================================
// Service Context
// ============================================================================

struct KeyServiceContext {
    db: sqlx::PgPool,
}

impl KeyServiceContext {
    async fn new() -> Result<Self> {
        let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

        let db = sqlx::PgPool::connect(&database_url)
            .await
            .context("Failed to connect to database")?;

        Ok(Self { db })
    }
}

// ============================================================================
// gRPC Service Implementation
// ============================================================================

#[derive(Clone)]
struct KeyGrpcService {
    context: Arc<KeyServiceContext>,
}

#[tonic::async_trait]
impl KeyService for KeyGrpcService {
    // =========================================================================
    // Pre-Key Bundle Operations
    // =========================================================================

    async fn get_pre_key_bundle(
        &self,
        request: Request<proto::GetPreKeyBundleRequest>,
    ) -> Result<Response<proto::GetPreKeyBundleResponse>, Status> {
        let req = request.into_inner();

        if req.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let bundle =
            core::get_prekey_bundle(&self.context.db, &req.user_id, req.device_id.as_deref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        match bundle {
            Some(b) => Ok(Response::new(proto::GetPreKeyBundleResponse {
                bundle: Some(proto::PreKeyBundle {
                    registration_id: 1,
                    identity_key: b.identity_key,
                    signed_pre_key: b.signed_prekey,
                    signed_pre_key_id: b.signed_prekey_id,
                    signed_pre_key_signature: b.signed_prekey_signature,
                    one_time_pre_key: b.one_time_prekey,
                    one_time_pre_key_id: b.one_time_prekey_id,
                    crypto_suite: b.suite_id,
                    generated_at: b.registered_at.timestamp(),
                }),
                device_id: b.device_id,
                has_one_time_key: b.one_time_prekey_id.is_some(),
            })),
            None => Err(Status::not_found("User or device not found")),
        }
    }

    // =========================================================================
    // One-Time Pre-Key Management
    // =========================================================================

    async fn upload_pre_keys(
        &self,
        request: Request<proto::UploadPreKeysRequest>,
    ) -> Result<Response<proto::UploadPreKeysResponse>, Status> {
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if req.pre_keys.is_empty() {
            return Err(Status::invalid_argument("pre_keys cannot be empty"));
        }

        // Convert proto prekeys to core types
        let prekeys: Vec<core::OneTimePreKey> = req
            .pre_keys
            .into_iter()
            .map(|k| core::OneTimePreKey {
                key_id: k.key_id,
                public_key: k.public_key,
            })
            .collect();

        let count = core::upload_prekeys(&self.context.db, &req.device_id, &prekeys)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Handle optional signed prekey update
        if let Some(spk) = req.signed_pre_key {
            let signed_key = core::SignedPreKey {
                key_id: spk.key_id,
                public_key: spk.public_key,
                signature: spk.signature,
            };
            core::rotate_signed_prekey(&self.context.db, &req.device_id, &signed_key, "upload")
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        Ok(Response::new(proto::UploadPreKeysResponse {
            success: true,
            pre_key_count: count,
            uploaded_at: chrono::Utc::now().timestamp(),
        }))
    }

    async fn get_pre_key_count(
        &self,
        request: Request<proto::GetPreKeyCountRequest>,
    ) -> Result<Response<proto::GetPreKeyCountResponse>, Status> {
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let (count, last_upload) = core::get_prekey_count(&self.context.db, &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::GetPreKeyCountResponse {
            count,
            recommended_minimum: 20,
            last_upload_at: last_upload.timestamp(),
        }))
    }

    // =========================================================================
    // Signed Pre-Key Rotation
    // =========================================================================

    async fn rotate_signed_pre_key(
        &self,
        request: Request<proto::RotateSignedPreKeyRequest>,
    ) -> Result<Response<proto::RotateSignedPreKeyResponse>, Status> {
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let new_key = req
            .new_signed_pre_key
            .ok_or_else(|| Status::invalid_argument("new_signed_pre_key is required"))?;

        if new_key.public_key.is_empty() || new_key.signature.is_empty() {
            return Err(Status::invalid_argument(
                "public_key and signature are required",
            ));
        }

        let reason = match req.reason {
            1 => "scheduled",
            2 => "security",
            3 => "user",
            4 => "reinstall",
            _ => "unspecified",
        };

        let signed_key = core::SignedPreKey {
            key_id: new_key.key_id,
            public_key: new_key.public_key,
            signature: new_key.signature,
        };

        let old_valid_until =
            core::rotate_signed_prekey(&self.context.db, &req.device_id, &signed_key, reason)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::RotateSignedPreKeyResponse {
            success: true,
            new_key_id: signed_key.key_id,
            old_key_valid_until: old_valid_until.timestamp(),
            rotated_at: chrono::Utc::now().timestamp(),
        }))
    }

    async fn get_signed_pre_key_age(
        &self,
        request: Request<proto::GetSignedPreKeyAgeRequest>,
    ) -> Result<Response<proto::GetSignedPreKeyAgeResponse>, Status> {
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let result = core::get_signed_prekey_age(&self.context.db, &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        match result {
            Some((uploaded_at, should_rotate)) => {
                let age = chrono::Utc::now() - uploaded_at;
                Ok(Response::new(proto::GetSignedPreKeyAgeResponse {
                    key_id: 1,
                    uploaded_at: uploaded_at.timestamp(),
                    age_seconds: age.num_seconds(),
                    should_rotate,
                    rotation_interval: 30 * 24 * 60 * 60, // 30 days
                }))
            }
            None => Err(Status::not_found("Device not found")),
        }
    }

    // =========================================================================
    // Identity Key Operations
    // =========================================================================

    async fn get_identity_key(
        &self,
        request: Request<proto::GetIdentityKeyRequest>,
    ) -> Result<Response<proto::GetIdentityKeyResponse>, Status> {
        let req = request.into_inner();

        if req.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let result =
            core::get_identity_key(&self.context.db, &req.user_id, req.device_id.as_deref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        match result {
            Some((identity_key, first_seen)) => {
                // Calculate fingerprint (first 32 chars of hex)
                let fingerprint = hex::encode(&identity_key)
                    .chars()
                    .take(32)
                    .collect::<Vec<_>>()
                    .chunks(4)
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_uppercase();

                Ok(Response::new(proto::GetIdentityKeyResponse {
                    identity_key,
                    fingerprint,
                    first_seen_at: first_seen.timestamp(),
                    key_changed: false, // TODO: track key changes
                    previous_fingerprint: None,
                }))
            }
            None => Err(Status::not_found("User or device not found")),
        }
    }

    async fn verify_safety_number(
        &self,
        request: Request<proto::VerifySafetyNumberRequest>,
    ) -> Result<Response<proto::VerifySafetyNumberResponse>, Status> {
        let req = request.into_inner();

        if req.our_user_id.is_empty() || req.their_user_id.is_empty() {
            return Err(Status::invalid_argument(
                "our_user_id and their_user_id are required",
            ));
        }
        if req.expected_safety_number.is_empty() {
            return Err(Status::invalid_argument(
                "expected_safety_number is required",
            ));
        }

        // Get both identity keys
        let our_key = core::get_identity_key(&self.context.db, &req.our_user_id, None)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("Our user not found"))?;

        let their_key = core::get_identity_key(&self.context.db, &req.their_user_id, None)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("Their user not found"))?;

        // Calculate safety number
        let actual = core::calculate_safety_number(
            &our_key.0,
            &their_key.0,
            &req.our_user_id,
            &req.their_user_id,
        );

        let matches = actual.replace(" ", "") == req.expected_safety_number.replace(" ", "");

        Ok(Response::new(proto::VerifySafetyNumberResponse {
            matches,
            actual_safety_number: actual,
            verified_at: chrono::Utc::now().timestamp(),
        }))
    }

    // =========================================================================
    // Batch Operations
    // =========================================================================

    async fn get_pre_key_bundles(
        &self,
        request: Request<proto::GetPreKeyBundlesRequest>,
    ) -> Result<Response<proto::GetPreKeyBundlesResponse>, Status> {
        let req = request.into_inner();

        if req.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let device_ids = if req.device_ids.is_empty() {
            None
        } else {
            Some(req.device_ids.as_slice())
        };

        let (bundles, unavailable) =
            core::get_prekey_bundles(&self.context.db, &req.user_id, device_ids)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        let proto_bundles = bundles
            .into_iter()
            .map(|b| proto::DevicePreKeyBundle {
                device_id: b.device_id.clone(),
                bundle: Some(proto::PreKeyBundle {
                    registration_id: 1,
                    identity_key: b.identity_key,
                    signed_pre_key: b.signed_prekey,
                    signed_pre_key_id: b.signed_prekey_id,
                    signed_pre_key_signature: b.signed_prekey_signature,
                    one_time_pre_key: b.one_time_prekey,
                    one_time_pre_key_id: b.one_time_prekey_id,
                    crypto_suite: b.suite_id,
                    generated_at: b.registered_at.timestamp(),
                }),
                platform: 0, // Unknown
            })
            .collect();

        Ok(Response::new(proto::GetPreKeyBundlesResponse {
            bundles: proto_bundles,
            unavailable_devices: unavailable,
        }))
    }
}

// ============================================================================
// Health Check
// ============================================================================

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "key-service",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn readiness_check(ctx: axum::extract::State<Arc<KeyServiceContext>>) -> impl IntoResponse {
    // Check database connection
    match sqlx::query("SELECT 1").fetch_one(&ctx.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready", "reason": "database unavailable" })),
        ),
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Key Service v{}", env!("CARGO_PKG_VERSION"));

    // Initialize context
    let context = Arc::new(KeyServiceContext::new().await?);

    // Create gRPC service
    let grpc_service = KeyGrpcService {
        context: context.clone(),
    };

    // gRPC server
    let grpc_addr: SocketAddr = env::var("KEY_SERVICE_GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50057".to_string())
        .parse()
        .context("Invalid KEY_SERVICE_GRPC_ADDR")?;

    info!("gRPC server listening on {}", grpc_addr);

    let grpc_server = tonic::transport::Server::builder()
        .add_service(KeyServiceServer::new(grpc_service))
        .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal());

    // HTTP health server
    let http_addr: SocketAddr = env::var("KEY_SERVICE_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8057".to_string())
        .parse()
        .context("Invalid KEY_SERVICE_HTTP_ADDR")?;

    let http_app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(context)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    info!("HTTP health server listening on {}", http_addr);

    let http_server = axum::serve(tokio::net::TcpListener::bind(http_addr).await?, http_app);

    // Run both servers, shutdown gracefully on SIGTERM/Ctrl-C
    tokio::select! {
        result = grpc_server => {
            result.context("gRPC server error")?;
        }
        result = http_server => {
            result.context("HTTP server error")?;
        }
        _ = construct_server_shared::shutdown_signal() => {
            info!("Shutdown signal received, stopping key-service...");
        }
    }

    Ok(())
}
