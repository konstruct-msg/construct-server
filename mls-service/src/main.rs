// ============================================================================
// MLS Service - RFC 9420 Group Messaging
// ============================================================================
//
// All RPCs in this service are stubs for MVP 0 (1-1 E2E chats).
// Full OpenMLS integration is planned for v2 (group chat release).
//
// Architecture (planned):
// - Group state stored encrypted in DB (ratchet tree, epoch)
// - Server-blind: cannot read group messages or member identities
// - Two-step join: InviteToGroup → AcceptGroupInvite with consent proof
// - Hard-delete on leave: no membership history stored server-side
// - Auto-expire messages after 90 days
//
// Port: 50058
// ============================================================================

use std::net::SocketAddr;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    mls_service_server::{MlsService, MlsServiceServer},
};

// ============================================================================
// Service Implementation (stubs)
// ============================================================================

#[derive(Default)]
struct MlsServiceImpl;

#[tonic::async_trait]
impl MlsService for MlsServiceImpl {
    // ── Group Lifecycle ───────────────────────────────────────────────────

    async fn create_group(
        &self,
        _request: Request<proto::CreateGroupRequest>,
    ) -> Result<Response<proto::CreateGroupResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn get_group_state(
        &self,
        _request: Request<proto::GetGroupStateRequest>,
    ) -> Result<Response<proto::GetGroupStateResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn dissolve_group(
        &self,
        _request: Request<proto::DissolveGroupRequest>,
    ) -> Result<Response<proto::DissolveGroupResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    // ── Membership ────────────────────────────────────────────────────────

    async fn invite_to_group(
        &self,
        _request: Request<proto::InviteToGroupRequest>,
    ) -> Result<Response<proto::InviteToGroupResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn accept_group_invite(
        &self,
        _request: Request<proto::AcceptGroupInviteRequest>,
    ) -> Result<Response<proto::AcceptGroupInviteResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn decline_group_invite(
        &self,
        _request: Request<proto::DeclineGroupInviteRequest>,
    ) -> Result<Response<proto::DeclineGroupInviteResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn get_pending_invites(
        &self,
        _request: Request<proto::GetPendingInvitesRequest>,
    ) -> Result<Response<proto::GetPendingInvitesResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn leave_group(
        &self,
        _request: Request<proto::LeaveGroupRequest>,
    ) -> Result<Response<proto::LeaveGroupResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn remove_member(
        &self,
        _request: Request<proto::RemoveMemberRequest>,
    ) -> Result<Response<proto::RemoveMemberResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    // ── Admin ─────────────────────────────────────────────────────────────

    async fn delegate_admin(
        &self,
        _request: Request<proto::DelegateAdminRequest>,
    ) -> Result<Response<proto::DelegateAdminResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    // ── State Sync ────────────────────────────────────────────────────────

    async fn submit_commit(
        &self,
        _request: Request<proto::SubmitCommitRequest>,
    ) -> Result<Response<proto::SubmitCommitResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    type FetchCommitsStream = tonic::codegen::BoxStream<proto::CommitEnvelope>;

    async fn fetch_commits(
        &self,
        _request: Request<proto::FetchCommitsRequest>,
    ) -> Result<Response<Self::FetchCommitsStream>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    // ── Messaging ─────────────────────────────────────────────────────────

    async fn send_group_message(
        &self,
        _request: Request<proto::SendGroupMessageRequest>,
    ) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    type FetchGroupMessagesStream = tonic::codegen::BoxStream<proto::GroupMessageEnvelope>;

    async fn fetch_group_messages(
        &self,
        _request: Request<proto::FetchGroupMessagesRequest>,
    ) -> Result<Response<Self::FetchGroupMessagesStream>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    type MessageStreamStream = tonic::codegen::BoxStream<proto::GroupStreamResponse>;

    async fn message_stream(
        &self,
        _request: Request<tonic::Streaming<proto::GroupStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    // ── KeyPackages ───────────────────────────────────────────────────────

    async fn publish_key_package(
        &self,
        _request: Request<proto::PublishKeyPackageRequest>,
    ) -> Result<Response<proto::PublishKeyPackageResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn consume_key_package(
        &self,
        _request: Request<proto::ConsumeKeyPackageRequest>,
    ) -> Result<Response<proto::ConsumeKeyPackageResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
    }

    async fn get_key_package_count(
        &self,
        _request: Request<proto::GetKeyPackageCountRequest>,
    ) -> Result<Response<proto::GetKeyPackageCountResponse>, Status> {
        Err(Status::unimplemented(
            "MLSService group chat — planned for v2",
        ))
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
                .unwrap_or_else(|_| "mls_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "50058".to_string())
        .parse()?;
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    info!("MLSService (stubs) listening on {}", addr);
    info!("Full OpenMLS integration planned for v2 (group chat release)");

    Server::builder()
        .add_service(MlsServiceServer::new(MlsServiceImpl))
        .serve_with_shutdown(addr, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
