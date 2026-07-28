// Media Service - gRPC Implementation
//
// SCALING NOTE: Currently shares the main PostgreSQL instance.
// When user growth justifies it, move media-service to a dedicated VPS with:
//   - SQLite (WAL mode) as the metadata store — single table, UUID lookups, TTL cleanup
//   - A large fast NVMe disk for file storage (replace local filesystem or MinIO)
//   - sqlx supports SQLite with minimal code changes (update PgPool → SqlitePool,
//     rewrite EXTRACT(EPOCH...) → strftime('%s',...), change UUID columns to TEXT)
// Multi-instance (load balancer) is only needed at ~10k+ concurrent uploads;
// until then a single dedicated instance with SQLite is sufficient.

use anyhow::{Context as _, Result};
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use chrono::{DateTime, Utc};
use construct_auth::AuthManager;
use construct_config::Config;
use construct_server_shared::db::DbPool;
use serde_json::json;
use std::{env, sync::Arc};
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use construct_server_shared::shared::proto::services::v1 as proto;
use proto::media_service_server::{MediaService, MediaServiceServer};

mod config;
mod core;
mod utils;

use config::MediaConfig;

pub struct MediaServiceContext {
    pub db_pool: Arc<DbPool>,
    pub media_config: Arc<MediaConfig>,
    pub public_host: String,
    /// Verifies Bearer access tokens for authenticated RPCs (token mint / delete).
    pub auth: Arc<AuthManager>,
}

#[derive(Clone)]
struct MediaGrpcService {
    context: Arc<MediaServiceContext>,
}

/// Require a cryptographically verified access token. Used for GenerateUploadToken
/// (and any future user-scoped media RPCs). Download remains capability-style
/// (media_id) by design — blobs are E2E ciphertext.
fn require_authed_user(
    auth: &AuthManager,
    metadata: &tonic::metadata::MetadataMap,
) -> Result<Uuid, Status> {
    construct_server_shared::auth_utils::extract_authed_caller(auth, metadata).map(|c| c.user_id)
}

// Constants for chunk sizes
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB chunks

#[tonic::async_trait]
impl MediaService for MediaGrpcService {
    // =========================================================================
    // Handler 1: GenerateUploadToken
    // =========================================================================
    async fn generate_upload_token(
        &self,
        request: Request<proto::GenerateUploadTokenRequest>,
    ) -> Result<Response<proto::GenerateUploadTokenResponse>, Status> {
        // Auth required: unauthenticated mint was an open storage-abuse vector.
        // UploadMedia still accepts only the short-lived HMAC upload_token capability.
        let user_id = require_authed_user(self.context.auth.as_ref(), request.metadata())?;
        let req = request.into_inner();

        // Validate expected size if provided
        if let Some(expected_size) = req.expected_size {
            if expected_size <= 0 {
                return Err(Status::invalid_argument("Expected size must be positive"));
            }
            if expected_size > self.context.media_config.max_file_size as i64 {
                return Err(Status::invalid_argument(format!(
                    "Expected size {} exceeds maximum {}",
                    expected_size, self.context.media_config.max_file_size
                )));
            }
        }

        // Generate token using core logic
        let token = core::generate_upload_token(&self.context.media_config.hmac_secret)
            .map_err(|e| Status::internal(format!("Failed to generate token: {}", e)))?;

        // Format: media_id|expires_at|signature
        let upload_token = format!(
            "{}|{}|{}",
            token.media_id, token.expires_at, token.signature
        );

        // Build expires_at as ISO 8601 timestamp
        let expires_at = DateTime::from_timestamp(token.expires_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        info!(
            user_id = %user_id,
            media_id = %token.media_id,
            "Issued media upload token"
        );

        Ok(Response::new(proto::GenerateUploadTokenResponse {
            upload_token,
            upload_url: format!(
                "grpc://{}/MediaService/UploadMedia",
                self.context.public_host
            ),
            max_file_size: self.context.media_config.max_file_size as i64,
            expires_at,
        }))
    }

    // =========================================================================
    // Handler 2: UploadMedia (client streaming)
    // =========================================================================
    async fn upload_media(
        &self,
        request: Request<tonic::Streaming<proto::UploadMediaRequest>>,
    ) -> Result<Response<proto::UploadMediaResponse>, Status> {
        let mut stream = request.into_inner();
        let mut upload_state: Option<core::UploadState> = None;
        let mut media_id: Option<String> = None;
        let mut expected_hash: Option<String> = None;

        // Process chunks
        while let Some(chunk_msg) = stream
            .message()
            .await
            .map_err(|e| Status::internal(format!("Stream error: {}", e)))?
        {
            // First chunk must contain upload_token
            if upload_state.is_none() {
                let token = chunk_msg.upload_token.ok_or_else(|| {
                    Status::invalid_argument("First chunk must contain upload_token")
                })?;

                // Validate token
                let (mid, _expires) =
                    core::validate_upload_token(&token, &self.context.media_config.hmac_secret)
                        .map_err(|e| Status::permission_denied(format!("Invalid token: {}", e)))?;

                media_id = Some(mid.clone());

                // Create upload state
                let mut state = core::UploadState::new(&self.context.media_config.storage_dir, mid)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("Failed to create upload state: {}", e))
                    })?;

                // Set expected size if provided
                state.expected_size = chunk_msg.total_size;

                upload_state = Some(state);
            }

            // Store expected hash from last chunk
            if chunk_msg.is_last {
                expected_hash = chunk_msg.file_hash.clone();
            }

            // Write chunk data
            if !chunk_msg.chunk.is_empty() {
                let state = upload_state.as_mut().unwrap();
                state
                    .write_chunk(&chunk_msg.chunk)
                    .await
                    .map_err(|e| Status::internal(format!("Write failed: {}", e)))?;

                // Check size limit
                if state.total_received > self.context.media_config.max_file_size {
                    // Abort upload and cleanup - take ownership
                    if let Some(s) = upload_state.take() {
                        let _ = s.abort().await;
                    }
                    return Err(Status::resource_exhausted("File size limit exceeded"));
                }
            }

            // Finish on last chunk
            if chunk_msg.is_last {
                break;
            }
        }

        // Finalize upload
        let state = upload_state.ok_or_else(|| Status::invalid_argument("No chunks received"))?;

        let mid = media_id.unwrap();
        let (file_path, computed_hash, total_size) = state
            .finalize()
            .await
            .map_err(|e| Status::internal(format!("Finalize failed: {}", e)))?;

        // Verify hash if provided
        if let Some(expected) = expected_hash
            && computed_hash != expected
        {
            // Delete the file since hash doesn't match
            let _ = tokio::fs::remove_file(&file_path).await;
            return Err(Status::data_loss(format!(
                "Hash mismatch: expected {}, got {}",
                expected, computed_hash
            )));
        }

        // Save metadata to database
        let storage_key = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&mid)
            .to_string();

        let metadata = core::save_metadata(
            &self.context.db_pool,
            &mid,
            total_size as i64,
            "local",
            &storage_key,
            &computed_hash,
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to save metadata: {}", e)))?;

        // Build expires_at as ISO 8601
        let expires_at = DateTime::from_timestamp(metadata.expires_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        info!(media_id = %mid, size = total_size, "Media uploaded successfully");

        Ok(Response::new(proto::UploadMediaResponse {
            media_id: mid,
            download_url: format!(
                "grpc://{}/MediaService/DownloadMedia",
                self.context.public_host
            ),
            file_size: total_size as i64,
            file_hash: computed_hash,
            expires_at,
        }))
    }

    // =========================================================================
    // Handler 3: DownloadMedia (server streaming)
    // =========================================================================
    type DownloadMediaStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::DownloadMediaResponse, Status>>;

    async fn download_media(
        &self,
        request: Request<proto::DownloadMediaRequest>,
    ) -> Result<Response<Self::DownloadMediaStream>, Status> {
        let req = request.into_inner();
        let media_id = req.media_id;

        // Validate media_id format
        if media_id.is_empty() {
            return Err(Status::invalid_argument("media_id is required"));
        }

        // Get metadata from database
        let metadata = core::get_metadata(&self.context.db_pool, &media_id)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?
            .ok_or_else(|| Status::not_found("Media not found"))?;

        // Build file path
        let file_path = self
            .context
            .media_config
            .storage_dir
            .join(&metadata.storage_key);

        // Check if file exists
        if !file_path.exists() {
            return Err(Status::not_found("Media file not found on disk"));
        }

        // Create download stream
        let mut download_stream = core::DownloadStream::new(&file_path, CHUNK_SIZE)
            .await
            .map_err(|e| Status::internal(format!("Failed to open file: {}", e)))?;

        let total_size = download_stream.total_size();
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        // Spawn streaming task
        tokio::spawn(async move {
            let mut chunk_number = 0i32;

            loop {
                match download_stream.read_chunk().await {
                    Ok(Some(data)) => {
                        let is_last = download_stream.is_complete();

                        let response = proto::DownloadMediaResponse {
                            chunk: data,
                            chunk_number,
                            is_last,
                            total_size: if chunk_number == 0 {
                                Some(total_size as i64)
                            } else {
                                None
                            },
                            content_type: if chunk_number == 0 {
                                Some("application/octet-stream".to_string())
                            } else {
                                None
                            },
                        };

                        if tx.send(Ok(response)).await.is_err() {
                            break;
                        }

                        chunk_number += 1;

                        if is_last {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Status::internal(format!("Read error: {}", e))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    // =========================================================================
    // Handler 4: DeleteMedia
    // =========================================================================
    async fn delete_media(
        &self,
        request: Request<proto::DeleteMediaRequest>,
    ) -> Result<Response<proto::DeleteMediaResponse>, Status> {
        // Require authenticated caller in addition to admin_token HMAC capability.
        // Prevents unauthenticated probing of the delete surface via Caddy.
        let _caller = require_authed_user(self.context.auth.as_ref(), request.metadata())?;
        let req = request.into_inner();

        // Validate admin token (HMAC capability bound to media_id + short TTL)
        // Admin token format: {media_id}|{timestamp}|{signature}
        if req.admin_token.is_empty() {
            return Err(Status::permission_denied("Admin token required"));
        }

        // Validate token format
        let parts: Vec<&str> = req.admin_token.split('|').collect();
        if parts.len() != 3 {
            return Err(Status::permission_denied("Invalid admin token format"));
        }

        let token_media_id = parts[0];
        let timestamp_str = parts[1];
        let signature = parts[2];

        // Verify media_id matches
        if token_media_id != req.media_id {
            return Err(Status::permission_denied("Token media_id mismatch"));
        }

        // Verify timestamp (allow 5 minute window)
        let timestamp: i64 = timestamp_str
            .parse()
            .map_err(|_| Status::permission_denied("Invalid timestamp in token"))?;
        let now = Utc::now().timestamp();
        if (now - timestamp).abs() > 300 {
            return Err(Status::permission_denied("Token expired"));
        }

        // Verify signature
        let message = format!("{}|{}", token_media_id, timestamp_str);
        let expected_sig = utils::compute_hmac(&message, &self.context.media_config.hmac_secret);
        if signature != expected_sig {
            return Err(Status::permission_denied("Invalid signature"));
        }

        // Delete media
        let deleted = core::delete_media(
            &self.context.db_pool,
            &self.context.media_config.storage_dir,
            &req.media_id,
        )
        .await
        .map_err(|e| Status::internal(format!("Delete failed: {}", e)))?;

        if deleted {
            info!(media_id = %req.media_id, "Media deleted");
            Ok(Response::new(proto::DeleteMediaResponse {
                success: true,
                message: "Media deleted successfully".to_string(),
            }))
        } else {
            Ok(Response::new(proto::DeleteMediaResponse {
                success: false,
                message: "Media not found".to_string(),
            }))
        }
    }

    // =========================================================================
    // Handler 5: GetMediaMetadata
    // =========================================================================
    async fn get_media_metadata(
        &self,
        request: Request<proto::GetMediaMetadataRequest>,
    ) -> Result<Response<proto::GetMediaMetadataResponse>, Status> {
        let req = request.into_inner();

        if req.media_id.is_empty() {
            return Err(Status::invalid_argument("media_id is required"));
        }

        // Get metadata from database
        let metadata = core::get_metadata(&self.context.db_pool, &req.media_id)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?
            .ok_or_else(|| Status::not_found("Media not found"))?;

        // Check if file exists on disk
        let file_path = self
            .context
            .media_config
            .storage_dir
            .join(&metadata.storage_key);
        let exists = file_path.exists();

        // Format timestamps as ISO 8601
        let created_at = DateTime::from_timestamp(metadata.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let expires_at = DateTime::from_timestamp(metadata.expires_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        Ok(Response::new(proto::GetMediaMetadataResponse {
            media_id: metadata.media_id,
            file_size: metadata.size_bytes,
            file_hash: metadata.file_hash,
            content_type: Some("application/octet-stream".to_string()),
            created_at,
            expires_at,
            exists,
        }))
    }
}

async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({"status": "ok", "service": "media"})),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let main_config = Config::from_env()?;
    let media_config = Arc::new(MediaConfig::from_env());

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&main_config.rust_log))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== Media Service Starting ===");
    info!("Storage: {}", media_config.storage_dir.display());

    tokio::fs::create_dir_all(&media_config.storage_dir).await?;

    let db_pool = Arc::new(DbPool::connect(&main_config.database_url).await?);
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await?;

    let public_host =
        env::var("MEDIA_PUBLIC_HOST").unwrap_or_else(|_| "localhost:50056".to_string());

    let auth = Arc::new(
        AuthManager::new(&main_config)
            .context("Failed to initialize AuthManager (set PASETO/JWT public keys)")?,
    );
    info!("JWT/PASETO verification enabled for media-service");

    let context = Arc::new(MediaServiceContext {
        db_pool,
        media_config: media_config.clone(),
        public_host,
        auth,
    });

    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("MEDIA_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50056".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_address).await?;

    tokio::spawn(async move {
        let service = MediaGrpcService {
            context: grpc_context,
        };
        if let Err(e) = construct_server_shared::grpc_server(
            main_config.grpc_keepalive_interval_secs,
            main_config.grpc_keepalive_timeout_secs,
        )
        .add_service(
            MediaServiceServer::new(service).max_decoding_message_size(2 * 1024 * 1024), // 2 MB per chunk
        )
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await
        {
            tracing::error!(error = %e, "gRPC server failed");
        }
    });
    info!("Media gRPC listening on [::]:50056");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        );

    let listener =
        construct_server_shared::mptcp_or_tcp_listener(&media_config.bind_address).await?;
    info!("Media REST listening on {}", media_config.bind_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use construct_config::{
        ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
        DeepLinksConfig, FederationConfig, LoggingConfig, MediaConfig as CfgMedia,
        MicroservicesConfig, MtlsConfig, RedisChannels, RedisKeyPrefixes, SecurityConfig,
    };

    fn make_auth() -> AuthManager {
        let kp = ed25519_compact::KeyPair::generate();
        let priv_pem = String::from_utf8(kp.sk.to_pem().as_bytes().to_vec()).unwrap();
        let pub_pem = String::from_utf8(kp.pk.to_pem().as_bytes().to_vec()).unwrap();
        let config = Config {
            database_url: String::new(),
            redis_url: String::new(),
            jwt_secret: "unused".into(),
            jwt_private_key: None,
            jwt_public_key: None,
            paseto_private_key: Some(priv_pem),
            paseto_public_key: Some(pub_pem),
            paseto_public_key_previous: vec![],
            token_issue_format: "paseto".into(),
            port: 0,
            bind_address: "127.0.0.1".into(),
            health_port: 0,
            heartbeat_interval_secs: 60,
            server_registry_ttl_secs: 120,
            message_ttl_days: 7,
            dedup_safety_margin_hours: 2,
            access_token_ttl_hours: 24,
            session_ttl_days: 30,
            refresh_token_ttl_days: 7,
            jwt_issuer: "construct-test".into(),
            online_channel: "online".into(),
            offline_queue_prefix: "queue:".into(),
            delivery_queue_prefix: "delivery:".into(),
            delivery_poll_interval_ms: 100,
            grpc_keepalive_interval_secs: 45,
            grpc_keepalive_timeout_secs: 5,
            rust_log: "error".into(),
            logging: LoggingConfig {
                enable_message_metadata: false,
                enable_user_identifiers: false,
                hash_salt: "test".into(),
            },
            security: SecurityConfig {
                prekey_ttl_days: 30,
                prekey_min_ttl_days: 7,
                prekey_max_ttl_days: 90,
                max_messages_per_hour: 1000,
                max_messages_per_ip_per_hour: 5000,
                max_key_rotations_per_day: 10,
                max_password_changes_per_day: 5,
                max_failed_login_attempts: 5,
                max_connections_per_user: 5,
                key_bundle_cache_hours: 1,
                rate_limit_block_duration_seconds: 3600,
                ip_rate_limiting_enabled: false,
                max_requests_per_ip_per_hour: 1000,
                combined_rate_limiting_enabled: false,
                max_requests_per_user_ip_per_hour: 500,
                max_long_poll_requests_per_window: 100,
                long_poll_rate_limit_window_secs: 60,
                request_signing_required: false,
                metrics_auth_enabled: false,
                metrics_ip_whitelist: vec![],
                metrics_bearer_token: None,
                max_pow_challenges_per_hour: 5,
                max_registrations_per_hour: 3,
                pow_difficulty: 1,
                username_hmac_secret: vec![0u8; 32],
                contact_hmac_secret: vec![0u8; 32],
                request_envelope_key: vec![0u8; 32],
            },
            apns: ApnsConfig {
                enabled: false,
                environment: ApnsEnvironment::Development,
                key_path: String::new(),
                key_id: String::new(),
                team_id: String::new(),
                bundle_id: String::new(),
                topic: String::new(),
                voip_topic: None,
                device_token_encryption_key: "0".repeat(64),
            },
            federation: FederationConfig {
                enabled: false,
                instance_domain: "test.local".into(),
                base_domain: "test.local".into(),
                signing_key_seed: None,
                max_requests_per_origin_per_hour: 1000,
                mtls: MtlsConfig {
                    required: false,
                    client_cert_path: None,
                    client_key_path: None,
                    verify_server_cert: false,
                    pinned_certs: Default::default(),
                },
            },
            db: DbConfig {
                max_connections: 1,
                min_connections: 0,
                acquire_timeout_secs: 5,
                idle_timeout_secs: 60,
            },
            deeplinks: DeepLinksConfig {
                apple_team_id: String::new(),
                android_package_name: String::new(),
                android_cert_fingerprint: String::new(),
            },
            redis_key_prefixes: RedisKeyPrefixes {
                processed_msg: "processed_msg:".into(),
                user: "user:".into(),
                session: "session:".into(),
                user_sessions: "user_sessions:".into(),
                msg_hash: "msg_hash:".into(),
                rate: "rate:".into(),
                blocked: "blocked:".into(),
                key_bundle: "key_bundle:".into(),
                connections: "connections:".into(),
            },
            redis_channels: RedisChannels {
                dead_letter_queue: "dlq".into(),
                delivery_message: "delivery_message:{}".into(),
                delivery_notification: "delivery_notification:{}".into(),
            },
            media: CfgMedia {
                enabled: false,
                base_url: String::new(),
                upload_token_secret: String::new(),
                max_file_size: 10 * 1024 * 1024,
                rate_limit_per_hour: 100,
            },
            csrf: CsrfConfig {
                enabled: false,
                secret: "test-csrf-secret-at-least-32-chars!!".into(),
                token_ttl_secs: 3600,
                allowed_origins: vec![],
                cookie_name: "csrf_token".into(),
                header_name: "X-CSRF-Token".into(),
            },
            messaging: Default::default(),
            microservices: MicroservicesConfig {
                enabled: false,
                auth_service_url: "http://localhost:8001".into(),
                messaging_service_url: "http://localhost:8002".into(),
                user_service_url: "http://localhost:8003".into(),
                notification_service_url: "http://localhost:8004".into(),
                discovery_mode: "static".into(),
                service_timeout_secs: 30,
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 5,
                    success_threshold: 2,
                    timeout_secs: 60,
                },
            },
            instance_domain: "test.local".into(),
            federation_base_domain: "test.local".into(),
            federation_enabled: false,
            deep_link_base_url: String::new(),
            veil_enabled: false,
            veil_port: 9443,
            veil_server_key: None,
            veil_iat_mode: 0,
            veil_upstream: "envoy:8080".into(),
            veil_tls_cert_path: None,
            veil_tls_key_path: None,
            veil_cover_upstream: None,
            veil_relay_addresses: vec![],
        };
        AuthManager::new(&config).expect("test auth")
    }

    #[test]
    fn require_authed_user_rejects_missing_bearer() {
        let auth = make_auth();
        let meta = tonic::metadata::MetadataMap::new();
        let err = require_authed_user(&auth, &meta).expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn require_authed_user_rejects_header_only_spoof() {
        let auth = make_auth();
        let uid = Uuid::new_v4();
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("x-user-id", uid.to_string().parse().unwrap());
        let err = require_authed_user(&auth, &meta).expect_err("header-only must fail");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn require_authed_user_accepts_valid_bearer() {
        let auth = make_auth();
        let uid = Uuid::new_v4();
        let (token, _, _) = auth.create_token_for_device(&uid, Some("device")).unwrap();
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let got = require_authed_user(&auth, &meta).expect("valid token");
        assert_eq!(got, uid);
    }

    #[test]
    fn upload_token_roundtrip_still_works() {
        // Capability path after mint remains HMAC-only (no Bearer on UploadMedia).
        let secret = "test-media-hmac-secret";
        let token = core::generate_upload_token(secret).unwrap();
        let wire = format!(
            "{}|{}|{}",
            token.media_id, token.expires_at, token.signature
        );
        let (mid, _) = core::validate_upload_token(&wire, secret).unwrap();
        assert_eq!(mid, token.media_id);
    }
}
