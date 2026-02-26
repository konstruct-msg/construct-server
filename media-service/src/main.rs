// Media Service - gRPC Implementation

use anyhow::Result;
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use chrono::{DateTime, Utc};
use construct_config::Config;
use construct_server_shared::db::DbPool;
use serde_json::json;
use std::{env, sync::Arc};
use tonic::{Request, Response, Status, transport::Server};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::shared::proto::services::v1 as proto;
use proto::media_service_server::{MediaService, MediaServiceServer};

mod config;
mod core;
mod utils;

use config::MediaConfig;

pub struct MediaServiceContext {
    pub db_pool: Arc<DbPool>,
    pub media_config: Arc<MediaConfig>,
}

#[derive(Clone)]
struct MediaGrpcService {
    context: Arc<MediaServiceContext>,
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

        Ok(Response::new(proto::GenerateUploadTokenResponse {
            upload_token,
            upload_url: "grpc://localhost:50056/MediaService/UploadMedia".to_string(),
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
            download_url: "grpc://localhost:50056/MediaService/DownloadMedia".to_string(),
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
        let req = request.into_inner();

        // Validate admin token (simple HMAC check)
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

    let context = Arc::new(MediaServiceContext {
        db_pool,
        media_config: media_config.clone(),
    });

    let grpc_context = context.clone();
    let grpc_addr = env::var("MEDIA_GRPC_BIND_ADDRESS")
        .unwrap_or_else(|_| "[::]:50056".to_string())
        .parse()?;

    tokio::spawn(async move {
        let service = MediaGrpcService {
            context: grpc_context,
        };
        if let Err(e) = Server::builder()
            .add_service(MediaServiceServer::new(service))
            .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal())
            .await
        {
            tracing::error!(error = %e, "gRPC server failed");
        }
    });
    info!("Media gRPC listening on [::]:50056");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check));

    let listener = tokio::net::TcpListener::bind(&media_config.bind_address).await?;
    info!("Media REST listening on {}", media_config.bind_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await?;
    Ok(())
}
