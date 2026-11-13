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
    self, RelayInfo, VeilServiceContext, VoucherError, bootstrap_voucher_flag_enabled,
    merge_legacy_relay, parse_relays_spec,
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
        .map_err(map_issue_err)?;

        let issued = bundle.primary;
        // No account and no identifier of the issued access in this line: a relay sees the
        // renewal arrive through its tunnel, so `user_id` + time here joins its log to an
        // account (decisions/veil-relay-sees-no-stable-device-id.md §2, todo 311).
        info!(
            front = %core::front_label(&self.context.issuer, &issued.relay_address),
            capability_version = issued.capability_version,
            alternates = bundle.alternates.len(),
            "issued veil capability"
        );

        let map_json_err = |e: serde_json::Error| Status::internal(format!("json error: {e}"));
        let signature = core::sign_entrypoint_tuple(
            &self.context.issuer,
            &issued.relay_address,
            &issued.sni,
            &issued.spki,
            issued.not_after,
        )
        .map_err(map_json_err)?;
        let alternates = bundle
            .alternates
            .into_iter()
            .map(|a| {
                let signature = core::sign_entrypoint_tuple(
                    &self.context.issuer,
                    &a.relay_address,
                    &a.sni,
                    &a.spki,
                    a.not_after,
                )
                .map_err(map_json_err)?;
                Ok(proto::EntryPoint {
                    capability: a.blob,
                    relay_address: a.relay_address,
                    spki: a.spki,
                    sni: a.sni,
                    not_after: a.not_after,
                    capability_version: a.capability_version,
                    signature,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        Ok(Response::new(proto::IssueVeilCapabilityResponse {
            capability: issued.blob,
            relay_address: issued.relay_address,
            spki: issued.spki,
            sni: issued.sni,
            not_after: issued.not_after,
            capability_version: issued.capability_version,
            alternates,
            signature,
        }))
    }

    async fn issue_bootstrap_voucher(
        &self,
        request: Request<proto::IssueBootstrapVoucherRequest>,
    ) -> Result<Response<proto::IssueBootstrapVoucherResponse>, Status> {
        let user_id =
            construct_server_shared::auth_utils::extract_user_id(&self.auth, request.metadata())?;

        if !self.context.bootstrap_voucher_enabled {
            construct_metrics::VEIL_BOOTSTRAP_VOUCHERS_FLAG_REJECTED_TOTAL.inc();
            return Err(Status::unimplemented(
                "issue bootstrap voucher is not enabled",
            ));
        }

        let issued = core::issue_bootstrap_voucher(&self.context, user_id)
            .await
            .map_err(|e| match e {
                VoucherError::NoRelaysConfigured => {
                    Status::failed_precondition("no relays configured on veil-service")
                }
                VoucherError::QuotaExceeded { retry_after } => {
                    construct_metrics::VEIL_BOOTSTRAP_VOUCHERS_RATE_LIMITED_TOTAL.inc();
                    Status::resource_exhausted(format!("retry_after={retry_after}"))
                }
                VoucherError::Db(e) => Status::internal(format!("db error: {e}")),
                VoucherError::Json(e) => Status::internal(format!("json error: {e}")),
            })?;

        construct_metrics::VEIL_BOOTSTRAP_VOUCHERS_ISSUED_TOTAL
            .with_label_values(&[core::VOUCHER_POOL])
            .inc();
        if self.context.relays.len() == 1 {
            construct_metrics::VEIL_BOOTSTRAP_VOUCHERS_N1_ISSUED_TOTAL.inc();
        }

        // Neither the issuer nor the voucher's ticket_id: another person presents that
        // ticket_id to a relay, and the pair would tie their IP to the issuer's account.
        info!(
            front = %core::front_label(&self.context.issuer, &issued.relay_address),
            not_after = issued.not_after,
            "issued bootstrap voucher"
        );

        Ok(Response::new(proto::IssueBootstrapVoucherResponse {
            config_uri: issued.config_uri,
            exp: issued.exp,
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
    let config = Arc::new(Config::from_env_for(construct_config::SecretNeeds::VEIL)?);

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
        // Labels, not addresses: this line ran on every boot and printed the whole
        // front list in the clear.
        info!(
            count = relays.len(),
            fronts = ?relays
                .keys()
                .map(|addr| core::front_label(&issuer, addr))
                .collect::<Vec<_>>(),
            "Configured VEIL fronts"
        );
        if relays.len() == 1 {
            info!(
                "Single front configured — EntryDirectory alternates will be empty until VEIL_RELAYS lists N>1"
            );
        }
    }

    let bootstrap_voucher_enabled =
        bootstrap_voucher_flag_enabled(env::var("VEIL_BOOTSTRAP_VOUCHER").ok().as_deref());
    info!(
        enabled = bootstrap_voucher_enabled,
        "IssueBootstrapVoucher flag"
    );

    let voucher_quota =
        core::voucher_quota_from_env(env::var("VEIL_VOUCHER_QUOTA").ok().as_deref());
    if voucher_quota != core::VOUCHER_QUOTA {
        info!(
            quota = voucher_quota,
            default = core::VOUCHER_QUOTA,
            "Bootstrap voucher quota overridden by VEIL_VOUCHER_QUOTA"
        );
    }

    let context = Arc::new(VeilServiceContext {
        db_pool,
        relays,
        issuer,
        ticket_ttl_secs: core::DEFAULT_TICKET_TTL_SECS,
        bootstrap_voucher_enabled,
        voucher_quota,
    });

    construct_metrics::force_veil_bootstrap_voucher_metrics();

    let auth = Arc::new(
        AuthManager::new(&config)
            .context("Failed to initialize AuthManager (set PASETO public keys)")?,
    );
    info!("PASETO verification enabled for veil-service");

    // gRPC server.
    let grpc_context = context.clone();
    let grpc_auth = auth.clone();
    let grpc_bind = env::var("VEIL_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50056".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind).await?;
    let ka = config.grpc_keepalive_interval_secs;
    let ka_to = config.grpc_keepalive_timeout_secs;
    // No blocklist: this service is given no Redis. The device row is the part that counts.
    let revocation = construct_server_shared::revocation::RevocationLayer::new(
        grpc_auth.clone(),
        construct_server_shared::revocation::RevocationCheck::new(context.db_pool.clone(), None),
    );
    tokio::spawn(async move {
        let service = VeilGrpcService {
            context: grpc_context,
            auth: grpc_auth,
        };
        if let Err(e) =
            construct_server_shared::revocation::guarded_grpc_server(ka, ka_to, revocation)
                .add_service(
                    VeilServiceServer::new(service)
                        .max_decoding_message_size(construct_server_shared::decode_limits::VEIL),
                )
                .serve_with_incoming_shutdown(
                    grpc_incoming,
                    construct_server_shared::shutdown_signal(),
                )
                .await
        {
            tracing::error!(error = %e, "Veil gRPC server failed");
        }
    });
    info!("Veil gRPC listening on {}", grpc_bind);

    {
        let pool = Arc::clone(&context.db_pool);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                match core::sweep_bootstrap_vouchers(&pool).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(deleted = n, "swept expired bootstrap vouchers")
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(error = %e, "bootstrap voucher sweep failed")
                    }
                }
            }
        });
    }

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

#[cfg(test)]
mod log_guard {
    /// No log line in veil-service names an account or an identifier of issued access.
    /// Either one, next to a time, joins a relay's log to an account
    /// (decisions/veil-relay-sees-no-stable-device-id.md §2). Counts go to metrics.
    #[test]
    fn no_log_line_names_an_account_or_issued_access() {
        const NAMES: [&str; 5] = [
            "user_id",
            "issuer_user_id",
            "ticket_id",
            "veil_pk",
            "device_id",
        ];
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut scanned = 0;
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            for mac in ["info!(", "warn!(", "debug!(", "error!(", "trace!("] {
                let mut from = 0;
                while let Some(at) = src[from..].find(mac) {
                    let open = from + at + mac.len();
                    let (mut depth, mut end) = (1, open);
                    for (i, c) in src[open..].char_indices() {
                        depth += match c {
                            '(' => 1,
                            ')' => -1,
                            _ => 0,
                        };
                        if depth == 0 {
                            end = open + i;
                            break;
                        }
                    }
                    let args = &src[open..end];
                    scanned += 1;
                    for name in NAMES {
                        let named = args.match_indices(name).any(|(i, _)| {
                            let before = args[..i].chars().next_back();
                            let after = args[i + name.len()..].chars().next();
                            let ident = |c: Option<char>| {
                                c.is_some_and(|c| c.is_alphanumeric() || c == '_')
                            };
                            !ident(before) && !ident(after)
                        });
                        if named {
                            let line = src[..open].lines().count();
                            found.push(format!("{}:{line} names {name}", path.display()));
                        }
                    }
                    from = end;
                }
            }
        }
        // The scan sees the service's log lines at all (main.rs alone has more than ten).
        assert!(scanned > 10, "scanned only {scanned} log macros");
        assert!(found.is_empty(), "{found:#?}");
    }
}
