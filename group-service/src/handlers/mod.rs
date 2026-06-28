mod admin;
mod channel_admin;
mod channel_invite_links;
mod channel_lifecycle;
mod comment_groups;
mod group_lifecycle;
mod key_packages;
mod membership;
mod messaging;
mod mls_sync;
mod posts;
mod subscriptions;
mod topics;

use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService, mls_service_server::MlsService,
};
use tonic::{Request, Response, Status, Streaming};

use crate::service::GroupServiceImpl;

// ═════════════════════════════════════════════════════════════════════════════
// MLS Service implementation
// ═════════════════════════════════════════════════════════════════════════════

#[tonic::async_trait]
impl MlsService for GroupServiceImpl {
    // ── Group Lifecycle ──

    async fn create_group(
        &self,
        request: Request<proto::CreateGroupRequest>,
    ) -> Result<Response<proto::CreateGroupResponse>, Status> {
        group_lifecycle::create_group(self, request).await
    }

    async fn get_group_state(
        &self,
        request: Request<proto::GetGroupStateRequest>,
    ) -> Result<Response<proto::GetGroupStateResponse>, Status> {
        group_lifecycle::get_group_state(self, request).await
    }

    async fn dissolve_group(
        &self,
        request: Request<proto::DissolveGroupRequest>,
    ) -> Result<Response<proto::DissolveGroupResponse>, Status> {
        group_lifecycle::dissolve_group(self, request).await
    }

    // ── Membership ──

    async fn invite_to_group(
        &self,
        request: Request<proto::InviteToGroupRequest>,
    ) -> Result<Response<proto::InviteToGroupResponse>, Status> {
        membership::invite_to_group(self, request).await
    }

    async fn accept_group_invite(
        &self,
        request: Request<proto::AcceptGroupInviteRequest>,
    ) -> Result<Response<proto::AcceptGroupInviteResponse>, Status> {
        membership::accept_group_invite(self, request).await
    }

    async fn decline_group_invite(
        &self,
        request: Request<proto::DeclineGroupInviteRequest>,
    ) -> Result<Response<proto::DeclineGroupInviteResponse>, Status> {
        membership::decline_group_invite(self, request).await
    }

    async fn get_pending_invites(
        &self,
        request: Request<proto::GetPendingInvitesRequest>,
    ) -> Result<Response<proto::GetPendingInvitesResponse>, Status> {
        membership::get_pending_invites(self, request).await
    }

    async fn leave_group(
        &self,
        request: Request<proto::LeaveGroupRequest>,
    ) -> Result<Response<proto::LeaveGroupResponse>, Status> {
        membership::leave_group(self, request).await
    }

    async fn remove_member(
        &self,
        request: Request<proto::RemoveMemberRequest>,
    ) -> Result<Response<proto::RemoveMemberResponse>, Status> {
        membership::remove_member(self, request).await
    }

    // ── Admin ──

    async fn delegate_admin(
        &self,
        request: Request<proto::DelegateAdminRequest>,
    ) -> Result<Response<proto::DelegateAdminResponse>, Status> {
        admin::delegate_admin(self, request).await
    }

    async fn transfer_ownership(
        &self,
        request: Request<proto::TransferOwnershipRequest>,
    ) -> Result<Response<proto::TransferOwnershipResponse>, Status> {
        admin::transfer_ownership(self, request).await
    }

    // ── MLS Sync ──

    async fn submit_commit(
        &self,
        request: Request<proto::SubmitCommitRequest>,
    ) -> Result<Response<proto::SubmitCommitResponse>, Status> {
        mls_sync::submit_commit(self, request).await
    }

    type FetchCommitsStream = mls_sync::FetchCommitsStream;

    async fn fetch_commits(
        &self,
        request: Request<proto::FetchCommitsRequest>,
    ) -> Result<Response<Self::FetchCommitsStream>, Status> {
        mls_sync::fetch_commits(self, request).await
    }

    // ── Messaging ──

    async fn send_group_message(
        &self,
        request: Request<proto::SendGroupMessageRequest>,
    ) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
        messaging::send_group_message(self, request).await
    }

    type FetchGroupMessagesStream = messaging::FetchGroupMessagesStream;

    async fn fetch_group_messages(
        &self,
        request: Request<proto::FetchGroupMessagesRequest>,
    ) -> Result<Response<Self::FetchGroupMessagesStream>, Status> {
        messaging::fetch_group_messages(self, request).await
    }

    type MessageStreamStream = messaging::MessageStreamStream;

    async fn message_stream(
        &self,
        request: Request<Streaming<proto::GroupStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        messaging::message_stream(self, request).await
    }

    // ── KeyPackages ──

    async fn publish_key_package(
        &self,
        request: Request<proto::PublishKeyPackageRequest>,
    ) -> Result<Response<proto::PublishKeyPackageResponse>, Status> {
        key_packages::publish_key_package(self, request).await
    }

    async fn consume_key_package(
        &self,
        request: Request<proto::ConsumeKeyPackageRequest>,
    ) -> Result<Response<proto::ConsumeKeyPackageResponse>, Status> {
        key_packages::consume_key_package(self, request).await
    }

    async fn get_key_package_count(
        &self,
        request: Request<proto::GetKeyPackageCountRequest>,
    ) -> Result<Response<proto::GetKeyPackageCountResponse>, Status> {
        key_packages::get_key_package_count(self, request).await
    }

    // ── Topics ──

    async fn create_topic(
        &self,
        request: Request<proto::CreateTopicRequest>,
    ) -> Result<Response<proto::CreateTopicResponse>, Status> {
        topics::create_topic(self, request).await
    }

    async fn list_topics(
        &self,
        request: Request<proto::ListTopicsRequest>,
    ) -> Result<Response<proto::ListTopicsResponse>, Status> {
        topics::list_topics(self, request).await
    }

    async fn archive_topic(
        &self,
        request: Request<proto::ArchiveTopicRequest>,
    ) -> Result<Response<proto::ArchiveTopicResponse>, Status> {
        topics::archive_topic(self, request).await
    }

    // ── Invite Links ──

    async fn create_invite_link(
        &self,
        request: Request<proto::CreateInviteLinkRequest>,
    ) -> Result<Response<proto::CreateInviteLinkResponse>, Status> {
        topics::create_invite_link(self, request).await
    }

    async fn revoke_invite_link(
        &self,
        request: Request<proto::RevokeInviteLinkRequest>,
    ) -> Result<Response<proto::RevokeInviteLinkResponse>, Status> {
        topics::revoke_invite_link(self, request).await
    }

    async fn resolve_invite_link(
        &self,
        request: Request<proto::ResolveInviteLinkRequest>,
    ) -> Result<Response<proto::ResolveInviteLinkResponse>, Status> {
        topics::resolve_invite_link(self, request).await
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Channel Service implementation
// ═════════════════════════════════════════════════════════════════════════════

#[tonic::async_trait]
impl ChannelService for GroupServiceImpl {
    // ── Channel Lifecycle ──

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

    // ── Subscription Management ──

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

    // ── Post Management ──

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

    // ── Comment Groups ──

    async fn get_comment_group(
        &self,
        request: Request<proto::GetCommentGroupRequest>,
    ) -> Result<Response<proto::GetCommentGroupResponse>, Status> {
        comment_groups::get_comment_group(self, request).await
    }

    // ── Admin Management ──

    async fn add_admin(
        &self,
        request: Request<proto::AddAdminRequest>,
    ) -> Result<Response<proto::AddAdminResponse>, Status> {
        channel_admin::add_admin(self, request).await
    }

    async fn remove_admin(
        &self,
        request: Request<proto::RemoveAdminRequest>,
    ) -> Result<Response<proto::RemoveAdminResponse>, Status> {
        channel_admin::remove_admin(self, request).await
    }

    async fn list_admins(
        &self,
        request: Request<proto::ListAdminsRequest>,
    ) -> Result<Response<proto::ListAdminsResponse>, Status> {
        channel_admin::list_admins(self, request).await
    }

    // ── Invite Links ──

    async fn create_invite_link(
        &self,
        request: Request<proto::ChannelServiceCreateInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceCreateInviteLinkResponse>, Status> {
        channel_invite_links::create_invite_link(self, request).await
    }

    async fn revoke_invite_link(
        &self,
        request: Request<proto::ChannelServiceRevokeInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceRevokeInviteLinkResponse>, Status> {
        channel_invite_links::revoke_invite_link(self, request).await
    }

    async fn resolve_invite_link(
        &self,
        request: Request<proto::ChannelServiceResolveInviteLinkRequest>,
    ) -> Result<Response<proto::ChannelServiceResolveInviteLinkResponse>, Status> {
        channel_invite_links::resolve_invite_link(self, request).await
    }
}
