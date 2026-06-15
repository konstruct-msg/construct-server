use anyhow::{Context, Result, anyhow};
use axum::{Json, Router, routing::get};
use construct_config::Config;
use construct_server_shared::db::DbPool;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::collections::HashMap;
use std::{env, sync::Arc};
use tonic::{Request, Response, Status, metadata::MetadataMap};
use tracing::info;
use uuid::Uuid;

use construct_server_shared::shared::proto::services::v1 as proto;
use proto::veil_service_server::{VeilService, VeilServiceServer};

mod core;
use core::{RelayInfo, VeilServiceContext};

/// Extract user_id from gRPC metadata (set by the gateway/envoy after JWT validation).
fn extract_user_id(metadata: &MetadataMap) -> Result<Uuid, Status> {
    let s = metadata
        .get("x-user-id")
        .ok_or_else(|| Status::unauthenticated("Missing x-user-id metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("Invalid x-user-id format"))?;
    Uuid::parse_str(s).map_err(|_| Status::unauthenticated("Invalid x-user-id UUID"))
}

#[derive(Clone)]
struct VeilGrpcService {
    context: Arc<VeilServiceContext>,
}

#[tonic::async_trait]
impl VeilService for VeilGrpcService {
    async fn issue_veil_capability(
        &self,
        request: Request<proto::IssueVeilCapabilityRequest>,
    ) -> Result<Response<proto::IssueVeilCapabilityResponse>, Status> {
        let user_id = extract_user_id(request.metadata())?;
        let req = request.into_inner();

        let issued = core::issue_capability(&self.context, user_id, &req.relay_address)
            .await
            .map_err(|e| match e {
                core::IssueError::UnknownRelay(r) => {
                    Status::invalid_argument(format!("unknown relay: {r}"))
                }
                core::IssueError::Db(e) => Status::internal(format!("db error: {e}")),
            })?;

        info!(
            user_id = %user_id,
            relay = %issued.relay_address,
            "issued veil capability"
        );

        Ok(Response::new(proto::IssueVeilCapabilityResponse {
            capability: issued.blob,
            relay_address: issued.relay_address,
            spki: issued.spki,
            sni: issued.sni,
            not_after: issued.not_after,
        }))
    }
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "service": "veil-service" }))
}

/// Build the relay registry from env (MVP single relay).
fn load_relays() -> HashMap<String, RelayInfo> {
    let mut relays = HashMap::new();
    if let Ok(addr) = env::var("VEIL_RELAY_ADDRESS")
        && !addr.is_empty()
    {
        relays.insert(
            addr,
            RelayInfo {
                scope: env::var("VEIL_RELAY_SCOPE").unwrap_or_default(),
                spki: env::var("VEIL_RELAY_SPKI").unwrap_or_default(),
                sni: env::var("VEIL_RELAY_SNI").unwrap_or_default(),
            },
        );
    }
    relays
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(Config::from_env()?);

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&config.rust_log))
        .init();

    info!("=== Veil Service Starting ===");
    info!("Port: {}", config.port);

    // Database + migrations.
    let db_pool = Arc::new(
        DbPool::connect(&config.database_url)
            .await
            .context("Failed to connect to database")?,
    );
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await
        .context("Failed to apply database migrations")?;
    info!("Database ready");

    // Issuer signing key (SECRET). Same Ed25519 key that signs the out-of-band
    // config blob — domain-separated in the capability message.
    let seed_hex = env::var("VEIL_ISSUER_SEED")
        .context("VEIL_ISSUER_SEED (issuer Ed25519 seed, 64 hex chars) is required")?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .context("VEIL_ISSUER_SEED must be valid hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("VEIL_ISSUER_SEED must decode to exactly 32 bytes"))?;
    let issuer = SigningKey::from_bytes(&seed);
    info!(
        "Issuer pubkey (relays pin this): {}",
        hex::encode(issuer.verifying_key().to_bytes())
    );

    let relays = load_relays();
    if relays.is_empty() {
        tracing::warn!(
            "No relays configured (VEIL_RELAY_ADDRESS unset) — IssueVeilCapability will reject all requests"
        );
    } else {
        info!("Configured relays: {:?}", relays.keys().collect::<Vec<_>>());
    }

    let context = Arc::new(VeilServiceContext {
        db_pool,
        relays,
        issuer,
        ticket_ttl_secs: core::DEFAULT_TICKET_TTL_SECS,
    });

    // gRPC server.
    let grpc_context = context.clone();
    let grpc_bind = env::var("VEIL_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50056".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind).await?;
    let ka = config.grpc_keepalive_interval_secs;
    let ka_to = config.grpc_keepalive_timeout_secs;
    tokio::spawn(async move {
        let service = VeilGrpcService {
            context: grpc_context,
        };
        if let Err(e) = construct_server_shared::grpc_server(ka, ka_to)
            .add_service(VeilServiceServer::new(service))
            .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
            .await
        {
            tracing::error!(error = %e, "Veil gRPC server failed");
        }
    });
    info!("Veil gRPC listening on {}", grpc_bind);

    // REST health server.
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        );

    info!("Veil Service REST listening on {}", config.bind_address);
    let listener = construct_server_shared::mptcp_or_tcp_listener(&config.bind_address)
        .await
        .context("Failed to bind REST address")?;
    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start axum server")?;

    Ok(())
}
