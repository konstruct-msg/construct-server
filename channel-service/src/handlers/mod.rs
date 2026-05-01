use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};
use tonic::{Request, Response, Status};

use crate::service::ChannelServiceImpl;

#[tonic::async_trait]
impl ChannelService for ChannelServiceImpl {
    // =========================================================================
    // Channel Lifecycle
    // =========================================================================

    async fn create_channel(
        &self,
        _request: Request<proto::CreateChannelRequest>,
    ) -> Result<Response<proto::CreateChannelResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn get_channel(
        &self,
        _request: Request<proto::GetChannelRequest>,
    ) -> Result<Response<proto::GetChannelResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn update_channel(
        &self,
        _request: Request<proto::UpdateChannelRequest>,
    ) -> Result<Response<proto::UpdateChannelResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn set_channel_visibility(
        &self,
        _request: Request<proto::SetChannelVisibilityRequest>,
    ) -> Result<Response<proto::SetChannelVisibilityResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn delete_channel(
        &self,
        _request: Request<proto::DeleteChannelRequest>,
    ) -> Result<Response<proto::DeleteChannelResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    // =========================================================================
    // Subscription Management
    // =========================================================================

    async fn subscribe_channel(
        &self,
        _request: Request<proto::SubscribeChannelRequest>,
    ) -> Result<Response<proto::SubscribeChannelResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn unsubscribe_channel(
        &self,
        _request: Request<proto::UnsubscribeChannelRequest>,
    ) -> Result<Response<proto::UnsubscribeChannelResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn list_subscriptions(
        &self,
        _request: Request<proto::ListSubscriptionsRequest>,
    ) -> Result<Response<proto::ListSubscriptionsResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn get_subscriber_count(
        &self,
        _request: Request<proto::GetSubscriberCountRequest>,
    ) -> Result<Response<proto::GetSubscriberCountResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    // =========================================================================
    // Post Management
    // =========================================================================

    async fn publish_post(
        &self,
        _request: Request<proto::PublishPostRequest>,
    ) -> Result<Response<proto::PublishPostResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn list_posts(
        &self,
        _request: Request<proto::ListPostsRequest>,
    ) -> Result<Response<proto::ListPostsResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn get_post(
        &self,
        _request: Request<proto::GetPostRequest>,
    ) -> Result<Response<proto::GetPostResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn delete_post(
        &self,
        _request: Request<proto::DeletePostRequest>,
    ) -> Result<Response<proto::DeletePostResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    // =========================================================================
    // Comment Groups
    // =========================================================================

    async fn get_comment_group(
        &self,
        _request: Request<proto::GetCommentGroupRequest>,
    ) -> Result<Response<proto::GetCommentGroupResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    // =========================================================================
    // Admin Management
    // =========================================================================

    async fn add_admin(
        &self,
        _request: Request<proto::AddAdminRequest>,
    ) -> Result<Response<proto::AddAdminResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn remove_admin(
        &self,
        _request: Request<proto::RemoveAdminRequest>,
    ) -> Result<Response<proto::RemoveAdminResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn list_admins(
        &self,
        _request: Request<proto::ListAdminsRequest>,
    ) -> Result<Response<proto::ListAdminsResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    // =========================================================================
    // Invite Links
    // =========================================================================

    async fn create_invite_link(
        &self,
        _request: Request<proto::ChannelServiceCreateInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceCreateInviteLinkResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn revoke_invite_link(
        &self,
        _request: Request<proto::ChannelServiceRevokeInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceRevokeInviteLinkResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn resolve_invite_link(
        &self,
        _request: Request<proto::ChannelServiceResolveInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceResolveInviteLinkResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }
}
