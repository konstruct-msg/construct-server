// ============================================================================
// MLS Service - RFC 9420 Group Messaging
// ============================================================================
//
// Phase 1: KeyPackage management fully implemented.
// All other RPCs (group lifecycle, membership, messaging) are stubs
// pending Phase 2+ implementation.
//
// Port: 50058
// ============================================================================

use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    mls_service_server::{MlsService, MlsServiceServer},
};

// ============================================================================
// Service State
// ============================================================================

#[derive(Clone)]
struct MlsServiceImpl {
    db: Arc<sqlx::PgPool>,
}

// ============================================================================
// Helpers
// ============================================================================

fn get_metadata_str<'a>(meta: &'a tonic::metadata::MetadataMap, key: &str) -> Option<&'a str> {
    meta.get(key).and_then(|v| v.to_str().ok())
}

fn extract_user_id(meta: &tonic::metadata::MetadataMap) -> Result<Uuid, Status> {
    get_metadata_str(meta, "x-user-id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))
}

// ============================================================================
// Service Implementation
// ============================================================================

#[tonic::async_trait]
impl MlsService for MlsServiceImpl {
    // ── Group Lifecycle ───────────────────────────────────────────────────

    async fn create_group(
        &self,
        _request: Request<proto::CreateGroupRequest>,
    ) -> Result<Response<proto::CreateGroupResponse>, Status> {
        Err(Status::unimplemented("CreateGroup — Phase 2"))
    }

    async fn get_group_state(
        &self,
        _request: Request<proto::GetGroupStateRequest>,
    ) -> Result<Response<proto::GetGroupStateResponse>, Status> {
        Err(Status::unimplemented("GetGroupState — Phase 2"))
    }

    async fn dissolve_group(
        &self,
        _request: Request<proto::DissolveGroupRequest>,
    ) -> Result<Response<proto::DissolveGroupResponse>, Status> {
        Err(Status::unimplemented("DissolveGroup — Phase 2"))
    }

    // ── Membership ────────────────────────────────────────────────────────

    async fn invite_to_group(
        &self,
        _request: Request<proto::InviteToGroupRequest>,
    ) -> Result<Response<proto::InviteToGroupResponse>, Status> {
        Err(Status::unimplemented("InviteToGroup — Phase 3"))
    }

    async fn accept_group_invite(
        &self,
        _request: Request<proto::AcceptGroupInviteRequest>,
    ) -> Result<Response<proto::AcceptGroupInviteResponse>, Status> {
        Err(Status::unimplemented("AcceptGroupInvite — Phase 3"))
    }

    async fn decline_group_invite(
        &self,
        _request: Request<proto::DeclineGroupInviteRequest>,
    ) -> Result<Response<proto::DeclineGroupInviteResponse>, Status> {
        Err(Status::unimplemented("DeclineGroupInvite — Phase 3"))
    }

    async fn get_pending_invites(
        &self,
        _request: Request<proto::GetPendingInvitesRequest>,
    ) -> Result<Response<proto::GetPendingInvitesResponse>, Status> {
        Err(Status::unimplemented("GetPendingInvites — Phase 3"))
    }

    async fn leave_group(
        &self,
        _request: Request<proto::LeaveGroupRequest>,
    ) -> Result<Response<proto::LeaveGroupResponse>, Status> {
        Err(Status::unimplemented("LeaveGroup — Phase 3"))
    }

    async fn remove_member(
        &self,
        _request: Request<proto::RemoveMemberRequest>,
    ) -> Result<Response<proto::RemoveMemberResponse>, Status> {
        Err(Status::unimplemented("RemoveMember — Phase 3"))
    }

    // ── Admin ─────────────────────────────────────────────────────────────

    async fn delegate_admin(
        &self,
        _request: Request<proto::DelegateAdminRequest>,
    ) -> Result<Response<proto::DelegateAdminResponse>, Status> {
        Err(Status::unimplemented("DelegateAdmin — Phase 4"))
    }

    // ── MLS Sync ──────────────────────────────────────────────────────────

    async fn submit_commit(
        &self,
        _request: Request<proto::SubmitCommitRequest>,
    ) -> Result<Response<proto::SubmitCommitResponse>, Status> {
        Err(Status::unimplemented("SubmitCommit — Phase 4"))
    }

    type FetchCommitsStream = tonic::codegen::BoxStream<proto::CommitEnvelope>;

    async fn fetch_commits(
        &self,
        _request: Request<proto::FetchCommitsRequest>,
    ) -> Result<Response<Self::FetchCommitsStream>, Status> {
        Err(Status::unimplemented("FetchCommits — Phase 4"))
    }

    // ── Messaging ─────────────────────────────────────────────────────────

    async fn send_group_message(
        &self,
        _request: Request<proto::SendGroupMessageRequest>,
    ) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
        Err(Status::unimplemented("SendGroupMessage — Phase 5"))
    }

    type FetchGroupMessagesStream = tonic::codegen::BoxStream<proto::GroupMessageEnvelope>;

    async fn fetch_group_messages(
        &self,
        _request: Request<proto::FetchGroupMessagesRequest>,
    ) -> Result<Response<Self::FetchGroupMessagesStream>, Status> {
        Err(Status::unimplemented("FetchGroupMessages — Phase 5"))
    }

    type MessageStreamStream = tonic::codegen::BoxStream<proto::GroupStreamResponse>;

    async fn message_stream(
        &self,
        _request: Request<tonic::Streaming<proto::GroupStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        Err(Status::unimplemented("MessageStream — Phase 5"))
    }

    // ── KeyPackages ───────────────────────────────────────────────────────

    async fn publish_key_package(
        &self,
        request: Request<proto::PublishKeyPackageRequest>,
    ) -> Result<Response<proto::PublishKeyPackageResponse>, Status> {
        let user_id = extract_user_id(request.metadata())?;
        let req = request.into_inner();

        let device_id = req.device_id;
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if req.key_packages.is_empty() {
            return Err(Status::invalid_argument(
                "at least one key_package required",
            ));
        }

        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::days(30);

        // Bulk insert — each KeyPackage is single-use (like one-time pre-keys)
        for kp in &req.key_packages {
            let kp_ref = sha256_bytes(kp);
            sqlx::query(
                r#"
                INSERT INTO group_key_packages
                    (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (key_package_ref) DO NOTHING
                "#,
            )
            .bind(user_id)
            .bind(&device_id)
            .bind(kp.as_slice())
            .bind(kp_ref.as_slice())
            .bind(now)
            .bind(expires_at)
            .execute(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        }

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM group_key_packages
            WHERE device_id = $1
              AND expires_at > NOW()
            "#,
        )
        .bind(&device_id)
        .fetch_one(self.db.as_ref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            published = req.key_packages.len(),
            total = count,
            "KeyPackages published"
        );

        Ok(Response::new(proto::PublishKeyPackageResponse {
            count: count as u32,
            published_at: now.timestamp(),
        }))
    }

    async fn consume_key_package(
        &self,
        request: Request<proto::ConsumeKeyPackageRequest>,
    ) -> Result<Response<proto::ConsumeKeyPackageResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        // Atomic consume: DELETE ... RETURNING (single-use guarantee)
        let row: Option<(Vec<u8>, String, Vec<u8>)> =
            if let Some(ref preferred) = req.preferred_device_id {
                // Prefer a specific device if requested
                sqlx::query_as(
                    r#"
                DELETE FROM group_key_packages
                WHERE id = (
                    SELECT id FROM group_key_packages
                    WHERE user_id = $1
                      AND device_id = $2
                      AND expires_at > NOW()
                    ORDER BY published_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING key_package, device_id, key_package_ref
                "#,
                )
                .bind(user_id)
                .bind(preferred)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            } else {
                sqlx::query_as(
                    r#"
                DELETE FROM group_key_packages
                WHERE id = (
                    SELECT id FROM group_key_packages
                    WHERE user_id = $1
                      AND expires_at > NOW()
                    ORDER BY published_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING key_package, device_id, key_package_ref
                "#,
                )
                .bind(user_id)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            };

        match row {
            None => Err(Status::not_found(
                "no KeyPackage available for this user; they must publish more",
            )),
            Some((key_package, device_id, key_package_ref)) => {
                info!(
                    target_user_id = %user_id,
                    device_id = %device_id,
                    "KeyPackage consumed"
                );
                Ok(Response::new(proto::ConsumeKeyPackageResponse {
                    key_package,
                    device_id,
                    key_package_ref,
                }))
            }
        }
    }

    async fn get_key_package_count(
        &self,
        request: Request<proto::GetKeyPackageCountRequest>,
    ) -> Result<Response<proto::GetKeyPackageCountResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let (count, last_published_at): (i64, Option<chrono::DateTime<chrono::Utc>>) =
            if let Some(ref device_id) = req.device_id {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*), MAX(published_at)
                    FROM group_key_packages
                    WHERE user_id = $1
                      AND device_id = $2
                      AND expires_at > NOW()
                    "#,
                )
                .bind(user_id)
                .bind(device_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            } else {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*), MAX(published_at)
                    FROM group_key_packages
                    WHERE user_id = $1
                      AND expires_at > NOW()
                    "#,
                )
                .bind(user_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            };

        Ok(Response::new(proto::GetKeyPackageCountResponse {
            count: count as u32,
            recommended_minimum: 20,
            last_published_at: last_published_at.map(|t| t.timestamp()).unwrap_or(0),
            cannot_be_invited: count == 0,
        }))
    }

    // ── Topics ────────────────────────────────────────────────────────────

    async fn create_topic(
        &self,
        _request: Request<proto::CreateTopicRequest>,
    ) -> Result<Response<proto::CreateTopicResponse>, Status> {
        Err(Status::unimplemented("CreateTopic — Phase 6"))
    }

    async fn list_topics(
        &self,
        _request: Request<proto::ListTopicsRequest>,
    ) -> Result<Response<proto::ListTopicsResponse>, Status> {
        Err(Status::unimplemented("ListTopics — Phase 6"))
    }

    async fn archive_topic(
        &self,
        _request: Request<proto::ArchiveTopicRequest>,
    ) -> Result<Response<proto::ArchiveTopicResponse>, Status> {
        Err(Status::unimplemented("ArchiveTopic — Phase 6"))
    }

    // ── Invite Links ──────────────────────────────────────────────────────

    async fn create_invite_link(
        &self,
        _request: Request<proto::CreateInviteLinkRequest>,
    ) -> Result<Response<proto::CreateInviteLinkResponse>, Status> {
        Err(Status::unimplemented("CreateInviteLink — Phase 6"))
    }

    async fn revoke_invite_link(
        &self,
        _request: Request<proto::RevokeInviteLinkRequest>,
    ) -> Result<Response<proto::RevokeInviteLinkResponse>, Status> {
        Err(Status::unimplemented("RevokeInviteLink — Phase 6"))
    }

    async fn resolve_invite_link(
        &self,
        _request: Request<proto::ResolveInviteLinkRequest>,
    ) -> Result<Response<proto::ResolveInviteLinkResponse>, Status> {
        Err(Status::unimplemented("ResolveInviteLink — Phase 6"))
    }
}

// ============================================================================
// SHA-256 helper (KeyPackage ref)
// ============================================================================

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mls_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = sqlx::PgPool::connect(&database_url).await?;

    // Run pending migrations on startup
    sqlx::migrate!("../shared/migrations").run(&db).await?;

    let db = Arc::new(db);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "50058".to_string())
        .parse()?;
    let grpc_bind_addr = format!("0.0.0.0:{}", port);
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_addr).await?;

    info!("MLSService listening on {}", grpc_bind_addr);

    // Small HTTP server for /health and /metrics
    let http_port: u16 = std::env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8097".into())
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
        info!("MLSService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    Server::builder()
        .add_service(MlsServiceServer::new(MlsServiceImpl { db }))
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
