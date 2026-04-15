// ============================================================================
// SentinelService — gRPC Server
// ============================================================================
//
// Privacy-first anti-spam. Metadata-only analysis; server never reads
// E2E encrypted message content.
//
// Port: 50059
// ============================================================================

mod core;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_auth::AuthManager;
use construct_config::Config;
use construct_server_shared::sentinel::{
    self as proto,
    sentinel_service_server::{SentinelService, SentinelServiceServer},
};

use core::SentinelCore;

// ============================================================================
// Helpers
// ============================================================================

/// Extract and verify device_id from both x-device-id header and JWT token.
/// This prevents header forgery attacks where an attacker spoofs x-device-id.
fn verified_caller_device_id<T>(req: &Request<T>, auth: &AuthManager) -> Result<String, Status> {
    // Extract header device_id
    let header_device_id = req
        .metadata()
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-device-id header"))?;

    // Extract JWT token from authorization header
    let token = req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing Authorization header"))?;

    // Verify JWT and extract claims
    let claims = auth
        .verify_token(&token)
        .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

    // Verify header device_id matches token's device_id
    auth.verify_device_id(&header_device_id, &claims)
        .map_err(|e| Status::permission_denied(format!("Device ID mismatch: {}", e)))
}

/// Legacy function for backward compatibility - use verified_caller_device_id instead.
#[allow(dead_code)]
fn caller_device_id<T>(req: &Request<T>) -> Result<String, Status> {
    req.metadata()
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-device-id header"))
}

fn require_admin<T>(req: &Request<T>) -> Result<(), Status> {
    let expected = env::var("ADMIN_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        return Err(Status::internal("Admin token not configured"));
    }
    let provided = req
        .metadata()
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != expected {
        return Err(Status::permission_denied("Invalid admin token"));
    }
    Ok(())
}

fn spam_category_str(cat: i32) -> &'static str {
    match cat {
        1 => "unwanted",
        2 => "harassment",
        3 => "scam",
        4 => "bot_suspected",
        5 => "impersonation",
        _ => "unspecified",
    }
}

// ============================================================================
// Service Context
// ============================================================================

struct SentinelServiceImpl {
    core: Arc<SentinelCore>,
    auth: Arc<AuthManager>,
}

// ============================================================================
// gRPC Handler Implementations
// ============================================================================

#[tonic::async_trait]
impl SentinelService for SentinelServiceImpl {
    // ── ReportSpam ────────────────────────────────────────────────────────────

    async fn report_spam(
        &self,
        request: Request<proto::ReportSpamRequest>,
    ) -> Result<Response<proto::ReportSpamResponse>, Status> {
        let reporter = verified_caller_device_id(&request, &self.auth)?;
        let req = request.into_inner();

        if req.reported_device_id.is_empty() {
            return Err(Status::invalid_argument("reported_device_id is required"));
        }
        if reporter == req.reported_device_id {
            return Err(Status::invalid_argument("Cannot report yourself"));
        }

        let category = spam_category_str(req.category);
        let report_id = self
            .core
            .report_spam(&reporter, &req.reported_device_id, category)
            .await
            .map_err(|e| {
                if e.to_string().contains("Report rate limit") {
                    Status::resource_exhausted("Report rate limit exceeded")
                } else {
                    Status::internal(e.to_string())
                }
            })?;

        Ok(Response::new(proto::ReportSpamResponse {
            accepted: true,
            report_id,
        }))
    }

    // ── BlockDevice ───────────────────────────────────────────────────────────

    async fn block_device(
        &self,
        request: Request<proto::BlockDeviceRequest>,
    ) -> Result<Response<proto::BlockDeviceResponse>, Status> {
        let blocker = verified_caller_device_id(&request, &self.auth)?;
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if blocker == req.device_id {
            return Err(Status::invalid_argument("Cannot block yourself"));
        }

        self.core
            .block_device(&blocker, &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::BlockDeviceResponse { success: true }))
    }

    // ── UnblockDevice ─────────────────────────────────────────────────────────

    async fn unblock_device(
        &self,
        request: Request<proto::UnblockDeviceRequest>,
    ) -> Result<Response<proto::UnblockDeviceResponse>, Status> {
        let blocker = verified_caller_device_id(&request, &self.auth)?;
        let req = request.into_inner();

        self.core
            .unblock_device(&blocker, &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::UnblockDeviceResponse {
            success: true,
        }))
    }

    // ── GetBlockedDevices ─────────────────────────────────────────────────────

    async fn get_blocked_devices(
        &self,
        request: Request<proto::GetBlockedDevicesRequest>,
    ) -> Result<Response<proto::GetBlockedDevicesResponse>, Status> {
        let blocker = verified_caller_device_id(&request, &self.auth)?;
        let req = request.into_inner();

        let (device_ids, has_more) = self
            .core
            .get_blocked_devices(&blocker, req.page, req.page_size)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::GetBlockedDevicesResponse {
            device_ids,
            has_more,
        }))
    }

    // ── GetTrustStatus ────────────────────────────────────────────────────────

    async fn get_trust_status(
        &self,
        request: Request<proto::GetTrustStatusRequest>,
    ) -> Result<Response<proto::GetTrustStatusResponse>, Status> {
        let device_id = verified_caller_device_id(&request, &self.auth)?;
        let trust = self
            .core
            .trust_level(&device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let (msgs_remaining, _) = self
            .core
            .msg_quota(&device_id, trust)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let (rcpt_remaining, _) = self
            .core
            .recipient_quota(&device_id, trust)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let trust_level_val = match trust {
            core::TrustLevel::New => 1,
            core::TrustLevel::Warming => 2,
            core::TrustLevel::Trusted => 3,
            core::TrustLevel::Flagged => 5,
            core::TrustLevel::Banned => 6,
        };

        Ok(Response::new(proto::GetTrustStatusResponse {
            trust_level: trust_level_val,
            messages_remaining_hour: msgs_remaining,
            new_recipients_remaining_day: rcpt_remaining,
            group_messages_remaining_day: trust.group_msg_limit_day(),
            restriction_expires_at: None,
            restriction_reason: None,
        }))
    }

    // ── CheckSendPermission ───────────────────────────────────────────────────

    async fn check_send_permission(
        &self,
        request: Request<proto::CheckSendPermissionRequest>,
    ) -> Result<Response<proto::CheckSendPermissionResponse>, Status> {
        let caller = verified_caller_device_id(&request, &self.auth)?;
        let req = request.into_inner();

        if req.target_device_id.is_empty() {
            return Err(Status::invalid_argument("target_device_id is required"));
        }

        let sender_user_id = if req.sender_user_id.is_empty() {
            None
        } else {
            Some(req.sender_user_id.as_str())
        };

        let perm = self
            .core
            .check_send_permission(&caller, &req.target_device_id, sender_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::CheckSendPermissionResponse {
            allowed: perm.allowed,
            denial_reason: perm.denial_reason,
            retry_after_seconds: perm.retry_after_seconds,
        }))
    }

    // ── GetProtectionStats (admin) ────────────────────────────────────────────

    async fn get_protection_stats(
        &self,
        request: Request<proto::GetProtectionStatsRequest>,
    ) -> Result<Response<proto::GetProtectionStatsResponse>, Status> {
        require_admin(&request)?;

        let stats = self
            .core
            .protection_stats()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::GetProtectionStatsResponse {
            spam_reports_24h: stats.spam_reports_24h,
            devices_flagged_24h: stats.devices_flagged_24h,
            devices_banned_7d: stats.devices_banned_7d,
            rate_limit_violations_24h: stats.rate_limit_violations_24h,
            blocks_created_24h: stats.blocks_created_24h,
        }))
    }

    // ── AdminBanDevice ────────────────────────────────────────────────────────

    async fn admin_ban_device(
        &self,
        request: Request<proto::AdminBanDeviceRequest>,
    ) -> Result<Response<proto::AdminBanDeviceResponse>, Status> {
        require_admin(&request)?;
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        self.core
            .set_banned(&req.device_id, &req.reason)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(device_id = %req.device_id, reason = %req.reason, "admin banned device");

        Ok(Response::new(proto::AdminBanDeviceResponse {
            success: true,
        }))
    }

    // ── AdminUnbanDevice ──────────────────────────────────────────────────────

    async fn admin_unban_device(
        &self,
        request: Request<proto::AdminUnbanDeviceRequest>,
    ) -> Result<Response<proto::AdminUnbanDeviceResponse>, Status> {
        require_admin(&request)?;
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        self.core
            .clear_ban(&req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(device_id = %req.device_id, "admin unbanned device");

        Ok(Response::new(proto::AdminUnbanDeviceResponse {
            success: true,
        }))
    }

    // ── AdminClearFlag ────────────────────────────────────────────────────────

    async fn admin_clear_flag(
        &self,
        request: Request<proto::AdminClearFlagRequest>,
    ) -> Result<Response<proto::AdminClearFlagResponse>, Status> {
        require_admin(&request)?;
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        self.core
            .clear_flag(&req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(device_id = %req.device_id, "admin cleared flag");

        Ok(Response::new(proto::AdminClearFlagResponse {
            success: true,
        }))
    }
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = env::var("DATABASE_URL")?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "50059".into())
        .parse()?;
    let grpc_bind_addr = format!("0.0.0.0:{}", port);
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_addr).await?;

    // Load config for JWT public key
    let config = Config::from_env().map_err(|e| anyhow::anyhow!("Config error: {}", e))?;
    let auth = Arc::new(
        AuthManager::new(&config).map_err(|e| anyhow::anyhow!("AuthManager error: {}", e))?,
    );

    let core = Arc::new(SentinelCore::new(&database_url, &redis_url).await?);

    info!("SentinelService listening on {}", grpc_bind_addr);

    // Small HTTP server for /health and /metrics
    let http_port: u16 = env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8090".into())
        .parse()?;
    let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port).parse()?;
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route(
                "/metrics",
                axum::routing::get(construct_server_shared::metrics::metrics_handler),
            );
        let listener = construct_server_shared::mptcp_or_tcp_listener(&http_addr.to_string())
            .await
            .unwrap();
        info!("SentinelService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    Server::builder()
        .add_service(SentinelServiceServer::new(SentinelServiceImpl {
            core,
            auth,
        }))
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
