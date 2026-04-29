use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};

use crate::service::MlsServiceImpl;

pub(crate) async fn create_topic(
    _svc: &MlsServiceImpl,
    _request: Request<proto::CreateTopicRequest>,
) -> Result<Response<proto::CreateTopicResponse>, Status> {
    Err(Status::unimplemented("CreateTopic — Phase 6"))
}

pub(crate) async fn list_topics(
    _svc: &MlsServiceImpl,
    _request: Request<proto::ListTopicsRequest>,
) -> Result<Response<proto::ListTopicsResponse>, Status> {
    Err(Status::unimplemented("ListTopics — Phase 6"))
}

pub(crate) async fn archive_topic(
    _svc: &MlsServiceImpl,
    _request: Request<proto::ArchiveTopicRequest>,
) -> Result<Response<proto::ArchiveTopicResponse>, Status> {
    Err(Status::unimplemented("ArchiveTopic — Phase 6"))
}

pub(crate) async fn create_invite_link(
    _svc: &MlsServiceImpl,
    _request: Request<proto::CreateInviteLinkRequest>,
) -> Result<Response<proto::CreateInviteLinkResponse>, Status> {
    Err(Status::unimplemented("CreateInviteLink — Phase 6"))
}

pub(crate) async fn revoke_invite_link(
    _svc: &MlsServiceImpl,
    _request: Request<proto::RevokeInviteLinkRequest>,
) -> Result<Response<proto::RevokeInviteLinkResponse>, Status> {
    Err(Status::unimplemented("RevokeInviteLink — Phase 6"))
}

pub(crate) async fn resolve_invite_link(
    _svc: &MlsServiceImpl,
    _request: Request<proto::ResolveInviteLinkRequest>,
) -> Result<Response<proto::ResolveInviteLinkResponse>, Status> {
    Err(Status::unimplemented("ResolveInviteLink — Phase 6"))
}
