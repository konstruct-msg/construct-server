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

use construct_server_shared::sentinel::{
    self as proto,
    sentinel_service_server::{SentinelService, SentinelServiceServer},
};

use core::SentinelCore;

// ============================================================================
// Helpers
// ============================================================================

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

fn restriction_type_str(rt: i32) -> &'static str {
    match rt {
        1 => "rate_limited",
        2 => "flagged",
        3 => "banned",
        _ => "unspecified",
    }
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
        let reporter = caller_device_id(&request)?;
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
        let blocker = caller_device_id(&request)?;
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
        let blocker = caller_device_id(&request)?;
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
        let blocker = caller_device_id(&request)?;
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
        let device_id = caller_device_id(&request)?;
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
        let caller = caller_device_id(&request)?;
        let req = request.into_inner();

        if req.target_device_id.is_empty() {
            return Err(Status::invalid_argument("target_device_id is required"));
        }

        let perm = self
            .core
            .check_send_permission(&caller, &req.target_device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::CheckSendPermissionResponse {
            allowed: perm.allowed,
            denial_reason: perm.denial_reason,
            retry_after_seconds: perm.retry_after_seconds,
        }))
    }

    // ── AppealRestriction ─────────────────────────────────────────────────────

    async fn appeal_restriction(
        &self,
        request: Request<proto::AppealRestrictionRequest>,
    ) -> Result<Response<proto::AppealRestrictionResponse>, Status> {
        let device_id = caller_device_id(&request)?;
        let req = request.into_inner();
        let restriction = restriction_type_str(req.restriction_type);

        let appeal_id = self
            .core
            .submit_appeal(&device_id, restriction, &req.context)
            .await
            .map_err(|e| {
                if e.to_string().contains("already pending") {
                    Status::already_exists(e.to_string())
                } else if e.to_string().contains("No active") {
                    Status::failed_precondition(e.to_string())
                } else {
                    Status::internal(e.to_string())
                }
            })?;

        Ok(Response::new(proto::AppealRestrictionResponse {
            submitted: true,
            appeal_id,
            status: "pending_review".to_string(),
        }))
    }

    // ── GetAppeals ────────────────────────────────────────────────────────────

    async fn get_appeals(
        &self,
        request: Request<proto::GetAppealsRequest>,
    ) -> Result<Response<proto::GetAppealsResponse>, Status> {
        let device_id = caller_device_id(&request)?;

        let appeals = self
            .core
            .get_appeals(&device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_appeals: Vec<proto::AppealInfo> = appeals
            .into_iter()
            .map(|a| {
                let restriction_type = match a.restriction_type.as_str() {
                    "rate_limited" => 1,
                    "flagged" => 2,
                    "banned" => 3,
                    _ => 0,
                };
                proto::AppealInfo {
                    id: a.id,
                    restriction_type,
                    context: a.context,
                    status: a.status,
                    created_at: Some(prost_types::Timestamp {
                        seconds: chrono::DateTime::parse_from_rfc3339(&a.created_at)
                            .map(|dt| dt.timestamp())
                            .unwrap_or(0),
                        nanos: 0,
                    }),
                    reviewed_at: a.reviewed_at.and_then(|rt| {
                        chrono::DateTime::parse_from_rfc3339(&rt).ok().map(|dt| {
                            prost_types::Timestamp {
                                seconds: dt.timestamp(),
                                nanos: 0,
                            }
                        })
                    }),
                }
            })
            .collect();

        Ok(Response::new(proto::GetAppealsResponse {
            appeals: proto_appeals,
        }))
    }

    // ── SubmitDispute ─────────────────────────────────────────────────────────

    async fn submit_dispute(
        &self,
        request: Request<proto::SubmitDisputeRequest>,
    ) -> Result<Response<proto::SubmitDisputeResponse>, Status> {
        let device_id = caller_device_id(&request)?;
        let req = request.into_inner();
        let restriction = restriction_type_str(req.restriction_type);

        if restriction == "unspecified" {
            return Err(Status::invalid_argument("restriction_type is required"));
        }

        let dispute_id = self
            .core
            .submit_dispute(&device_id, restriction, &req.evidence_text)
            .await
            .map_err(|e| {
                if e.to_string().contains("Too many pending") {
                    Status::resource_exhausted(e.to_string())
                } else if e.to_string().contains("not banned")
                    || e.to_string().contains("not flagged")
                {
                    Status::failed_precondition(e.to_string())
                } else {
                    Status::internal(e.to_string())
                }
            })?;

        // Check if auto-resolved (device was unbanned during dispute)
        let trust = self
            .core
            .trust_level(&device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let auto_resolved = match restriction {
            "banned" => trust != core::TrustLevel::Banned,
            "flagged" => trust != core::TrustLevel::Flagged,
            _ => false,
        };

        let status = if auto_resolved {
            "approved"
        } else {
            "pending_review"
        };

        Ok(Response::new(proto::SubmitDisputeResponse {
            submitted: true,
            dispute_id,
            status: status.to_string(),
            auto_resolved,
        }))
    }

    // ── GetDisputes ───────────────────────────────────────────────────────────

    async fn get_disputes(
        &self,
        request: Request<proto::GetDisputesRequest>,
    ) -> Result<Response<proto::GetDisputesResponse>, Status> {
        let device_id = caller_device_id(&request)?;

        let disputes = self
            .core
            .get_disputes(&device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_disputes: Vec<proto::DisputeInfo> = disputes
            .into_iter()
            .map(|d| {
                let restriction_type = match d.restriction_type.as_str() {
                    "rate_limited" => 1,
                    "flagged" => 2,
                    "banned" => 3,
                    _ => 0,
                };
                proto::DisputeInfo {
                    id: d.id,
                    restriction_type,
                    evidence_text: d.evidence_text,
                    auto_evidence: String::new(), // not exposed to client
                    status: d.status,
                    created_at: Some(prost_types::Timestamp {
                        seconds: chrono::DateTime::parse_from_rfc3339(&d.created_at)
                            .map(|dt| dt.timestamp())
                            .unwrap_or(0),
                        nanos: 0,
                    }),
                }
            })
            .collect();

        Ok(Response::new(proto::GetDisputesResponse {
            disputes: proto_disputes,
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
            appeals_pending: stats.appeals_pending,
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
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    let core = Arc::new(SentinelCore::new(&database_url, &redis_url).await?);

    info!("SentinelService listening on {}", addr);

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
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        info!("SentinelService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    Server::builder()
        .add_service(SentinelServiceServer::new(SentinelServiceImpl { core }))
        .serve_with_shutdown(addr, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
