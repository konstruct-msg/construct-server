use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};

use crate::service::MlsServiceImpl;

pub(crate) type FetchGroupMessagesStream = tonic::codegen::BoxStream<proto::GroupMessageEnvelope>;
pub(crate) type MessageStreamStream = tonic::codegen::BoxStream<proto::GroupStreamResponse>;

pub(crate) async fn send_group_message(
    _svc: &MlsServiceImpl,
    _request: Request<proto::SendGroupMessageRequest>,
) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
    Err(Status::unimplemented("SendGroupMessage — Phase 5"))
}

pub(crate) async fn fetch_group_messages(
    _svc: &MlsServiceImpl,
    _request: Request<proto::FetchGroupMessagesRequest>,
) -> Result<Response<FetchGroupMessagesStream>, Status> {
    Err(Status::unimplemented("FetchGroupMessages — Phase 5"))
}

pub(crate) async fn message_stream(
    _svc: &MlsServiceImpl,
    _request: Request<tonic::Streaming<proto::GroupStreamRequest>>,
) -> Result<Response<MessageStreamStream>, Status> {
    Err(Status::unimplemented("MessageStream — Phase 5"))
}
