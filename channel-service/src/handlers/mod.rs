mod admin;
mod channel_lifecycle;
mod comment_groups;
mod invite_links;
mod posts;
mod subscriptions;

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
        request: Request<proto::CreateChannelRequest>,
    ) -> Result<Response<proto::CreateChannelResponse>, Status> {
        channel_lifecycle::create_channel(self, request).await
    }

    async fn get_channel(
        &self,
        request: Request<proto::GetChannelRequest>,
    ) -> Result<Response<proto::GetChannelResponse>, Status> {
        channel_lifecycle::get_channel(self, request).await
    }

    async fn update_channel(
        &self,
        request: Request<proto::UpdateChannelRequest>,
    ) -> Result<Response<proto::UpdateChannelResponse>, Status> {
        channel_lifecycle::update_channel(self, request).await
    }

    async fn set_channel_visibility(
        &self,
        request: Request<proto::SetChannelVisibilityRequest>,
    ) -> Result<Response<proto::SetChannelVisibilityResponse>, Status> {
        channel_lifecycle::set_channel_visibility(self, request).await
    }

    async fn delete_channel(
        &self,
        request: Request<proto::DeleteChannelRequest>,
    ) -> Result<Response<proto::DeleteChannelResponse>, Status> {
        channel_lifecycle::delete_channel(self, request).await
    }

    // =========================================================================
    // Subscription Management
    // =========================================================================

    async fn subscribe_channel(
        &self,
        request: Request<proto::SubscribeChannelRequest>,
    ) -> Result<Response<proto::SubscribeChannelResponse>, Status> {
        subscriptions::subscribe_channel(self, request).await
    }

    async fn unsubscribe_channel(
        &self,
        request: Request<proto::UnsubscribeChannelRequest>,
    ) -> Result<Response<proto::UnsubscribeChannelResponse>, Status> {
        subscriptions::unsubscribe_channel(self, request).await
    }

    async fn list_subscriptions(
        &self,
        request: Request<proto::ListSubscriptionsRequest>,
    ) -> Result<Response<proto::ListSubscriptionsResponse>, Status> {
        subscriptions::list_subscriptions(self, request).await
    }

    async fn get_subscriber_count(
        &self,
        request: Request<proto::GetSubscriberCountRequest>,
    ) -> Result<Response<proto::GetSubscriberCountResponse>, Status> {
        subscriptions::get_subscriber_count(self, request).await
    }

    // =========================================================================
    // Post Management
    // =========================================================================

    async fn publish_post(
        &self,
        request: Request<proto::PublishPostRequest>,
    ) -> Result<Response<proto::PublishPostResponse>, Status> {
        posts::publish_post(self, request).await
    }

    async fn list_posts(
        &self,
        request: Request<proto::ListPostsRequest>,
    ) -> Result<Response<proto::ListPostsResponse>, Status> {
        posts::list_posts(self, request).await
    }

    async fn get_post(
        &self,
        request: Request<proto::GetPostRequest>,
    ) -> Result<Response<proto::GetPostResponse>, Status> {
        posts::get_post(self, request).await
    }

    async fn delete_post(
        &self,
        request: Request<proto::DeletePostRequest>,
    ) -> Result<Response<proto::DeletePostResponse>, Status> {
        posts::delete_post(self, request).await
    }

    // =========================================================================
    // Comment Groups
    // =========================================================================

    async fn get_comment_group(
        &self,
        request: Request<proto::GetCommentGroupRequest>,
    ) -> Result<Response<proto::GetCommentGroupResponse>, Status> {
        comment_groups::get_comment_group(self, request).await
    }

    // =========================================================================
    // Admin Management
    // =========================================================================

    async fn add_admin(
        &self,
        request: Request<proto::AddAdminRequest>,
    ) -> Result<Response<proto::AddAdminResponse>, Status> {
        admin::add_admin(self, request).await
    }

    async fn remove_admin(
        &self,
        request: Request<proto::RemoveAdminRequest>,
    ) -> Result<Response<proto::RemoveAdminResponse>, Status> {
        admin::remove_admin(self, request).await
    }

    async fn list_admins(
        &self,
        request: Request<proto::ListAdminsRequest>,
    ) -> Result<Response<proto::ListAdminsResponse>, Status> {
        admin::list_admins(self, request).await
    }

    // =========================================================================
    // Invite Links
    // =========================================================================

    async fn create_invite_link(
        &self,
        request: Request<proto::ChannelServiceCreateInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceCreateInviteLinkResponse>, Status> {
        invite_links::create_invite_link(self, request).await
    }

    async fn revoke_invite_link(
        &self,
        request: Request<proto::ChannelServiceRevokeInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceRevokeInviteLinkResponse>, Status> {
        invite_links::revoke_invite_link(self, request).await
    }

    async fn resolve_invite_link(
        &self,
        request: Request<proto::ChannelServiceResolveInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceResolveInviteLinkResponse>, Status> {
        invite_links::resolve_invite_link(self, request).await
    }
}
