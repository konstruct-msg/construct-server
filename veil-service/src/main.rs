use anyhow::{Context, Result, anyhow};
use axum::{Json, Router, routing::get};
use construct_auth::AuthManager;
use construct_config::Config;
use construct_server_shared::db::DbPool;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{env, sync::Arc};
use tonic::{Request, Response, Status};
use tracing::info;

use construct_server_shared::shared::proto::services::v1 as proto;
use proto::veil_service_server::{VeilService, VeilServiceServer};
use veil_service::core::{
    self, RelayInfo, VeilServiceContext, merge_legacy_relay, parse_relays_spec,
};

#[derive(Clone)]
struct VeilGrpcService {
    context: Arc<VeilServiceContext>,
    auth: Arc<AuthManager>,
}

#[tonic::async_trait]
impl VeilService for VeilGrpcService {
    async fn issue_veil_capability(
        &self,
        request: Request<proto::IssueVeilCapabilityRequest>,
    ) -> Result<Response<proto::IssueVeilCapabilityResponse>, Status> {
        let user_id =
            construct_server_shared::auth_utils::extract_user_id(&self.auth, request.metadata())?;
        let req = request.into_inner();

        let map_issue_err = |e: core::IssueError| match e {
            core::IssueError::UnknownRelay(r) => {
                Status::invalid_argument(format!("unknown relay: {r}"))
            }
            core::IssueError::Db(e) => Status::internal(format!("db error: {e}")),
            core::IssueError::InvalidVeilPk(n) => {
                Status::invalid_argument(format!("invalid veil_pk length: {n}"))
            }
            core::IssueError::InvalidRole(r) => {
                Status::invalid_argument(format!("invalid role: {r}"))
            }
            core::IssueError::NoRelaysConfigured => {
                Status::failed_precondition("no relays configured on veil-service")
            }
            core::IssueError::RelayAddressRequired => Status::invalid_argument(
                "relay_address required when multiple relays are configured",
            ),
        };

        // EntryDirectory v1: issue the requested (primary) capability plus up to K
        // pre-issued alternate fronts on other configured relays. A non-empty veil_pk
        // requests key-bound CapabilityV2 (AUTH v3) for all of them; otherwise bearer
        // B2. Empty relay_address is resolved to the sole configured relay (N=1) so
        // auto first-issue still works if the client omits it.
        // See decisions/{veil-ticket-provisioning-system,entry-directory-design}.md.
        let bundle = core::issue_bundle(
            &self.context,
            user_id,
            &req.relay_address,
            &req.veil_pk,
            req.role,
            core::DEFAULT_ALTERNATES_K,
        )
        .await
        .map_err(map_issue_err)?;

        let issued = bundle.primary;
        info!(
            user_id = %user_id,
            relay = %issued.relay_address,
            capability_version = issued.capability_version,
            alternates = bundle.alternates.len(),
            "issued veil capability"
        );

        let alternates = bundle
            .alternates
            .into_iter()
            .map(|a| proto::EntryPoint {
                capability: a.blob,
                relay_address: a.relay_address,
                spki: a.spki,
                sni: a.sni,
                not_after: a.not_after,
                capability_version: a.capability_version,
            })
            .collect();

        Ok(Response::new(proto::IssueVeilCapabilityResponse {
            capability: issued.blob,
            relay_address: issued.relay_address,
            spki: issued.spki,
            sni: issued.sni,
            not_after: issued.not_after,
            capability_version: issued.capability_version,
            alternates,
        }))
    }
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "service": "veil-service" }))
}

/// Build the relay registry from env.
///
/// Two sources, merged (EntryDirectory v1 needs N>1 fronts — see
/// `decisions/entry-directory-design.md`):
///   - `VEIL_RELAYS`: `;`-separated records, each `address,scope,spki,sni`. The
///     multi-front source; whitespace around fields is trimmed, blank records skipped.
///   - `VEIL_RELAY_ADDRESS` (+ `_SCOPE`/`_SPKI`/`_SNI`): the legacy single-relay vars,
///     kept for back-compat. Added if `VEIL_RELAYS` did not already define that address.
fn load_relays() -> std::collections::HashMap<String, RelayInfo> {
    let mut relays = if let Ok(spec) = env::var("VEIL_RELAYS") {
        let (map, skipped) = parse_relays_spec(&spec);
        if skipped > 0 {
            tracing::warn!(
                skipped,
                "skipped malformed VEIL_RELAYS record(s) (want address,scope,spki,sni)"
            );
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    merge_legacy_relay(
        &mut relays,
        &env::var("VEIL_RELAY_ADDRESS").unwrap_or_default(),
        &env::var("VEIL_RELAY_SCOPE").unwrap_or_default(),
        &env::var("VEIL_RELAY_SPKI").unwrap_or_default(),
        &env::var("VEIL_RELAY_SNI").unwrap_or_default(),
    );

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
            "No relays configured (set VEIL_RELAYS and/or VEIL_RELAY_ADDRESS) — IssueVeilCapability will reject all requests"
        );
    } else {
        info!(
            count = relays.len(),
            relays = ?relays.keys().collect::<Vec<_>>(),
            "Configured VEIL fronts"
        );
        if relays.len() == 1 {
            info!(
                "Single front configured — EntryDirectory alternates will be empty until VEIL_RELAYS lists N>1"
            );
        }
    }

    let context = Arc::new(VeilServiceContext {
        db_pool,
        relays,
        issuer,
        ticket_ttl_secs: core::DEFAULT_TICKET_TTL_SECS,
    });

    let auth = Arc::new(
        AuthManager::new(&config)
            .context("Failed to initialize AuthManager (set PASETO/JWT public keys)")?,
    );
    info!("JWT/PASETO verification enabled for veil-service");

    // gRPC server.
    let grpc_context = context.clone();
    let grpc_auth = auth.clone();
    let grpc_bind = env::var("VEIL_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50056".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind).await?;
    let ka = config.grpc_keepalive_interval_secs;
    let ka_to = config.grpc_keepalive_timeout_secs;
    tokio::spawn(async move {
        let service = VeilGrpcService {
            context: grpc_context,
            auth: grpc_auth,
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
