// Media Service - gRPC Stub Implementation
// TODO: Implement full streaming handlers in next session

use anyhow::{Context, Result};
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
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

#[tonic::async_trait]
impl MediaService for MediaGrpcService {
    async fn generate_upload_token(
        &self,
        _request: Request<proto::GenerateUploadTokenRequest>,
    ) -> Result<Response<proto::GenerateUploadTokenResponse>, Status> {
        Err(Status::unimplemented(
            "GenerateUploadToken not implemented yet",
        ))
    }

    async fn upload_media(
        &self,
        _request: Request<tonic::Streaming<proto::UploadMediaRequest>>,
    ) -> Result<Response<proto::UploadMediaResponse>, Status> {
        Err(Status::unimplemented("UploadMedia not implemented yet"))
    }

    type DownloadMediaStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::DownloadMediaResponse, Status>>;

    async fn download_media(
        &self,
        _request: Request<proto::DownloadMediaRequest>,
    ) -> Result<Response<Self::DownloadMediaStream>, Status> {
        Err(Status::unimplemented("DownloadMedia not implemented yet"))
    }

    async fn delete_media(
        &self,
        _request: Request<proto::DeleteMediaRequest>,
    ) -> Result<Response<proto::DeleteMediaResponse>, Status> {
        Err(Status::unimplemented("DeleteMedia not implemented yet"))
    }

    async fn get_media_metadata(
        &self,
        _request: Request<proto::GetMediaMetadataRequest>,
    ) -> Result<Response<proto::GetMediaMetadataResponse>, Status> {
        Err(Status::unimplemented(
            "GetMediaMetadata not implemented yet",
        ))
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

    info!("=== Media Service Starting (Stub) ===");
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
            .serve(grpc_addr)
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

    axum::serve(listener, app).await?;
    Ok(())
}
