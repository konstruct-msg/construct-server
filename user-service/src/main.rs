// User management service for microservices architecture.
// Handles:
// - User profiles management
// - Public keys (key bundles)
// - Account management (get, update, delete)
//
// Architecture:
// - Stateless
// - Horizontally scalable
// - Redis caching for key bundles
//
// ============================================================================

mod handlers;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use construct_config::Config;
use construct_crypto::hash_username;
use construct_db::{
    self as db_agility, create_contact_request, get_contact_request_sender,
    get_pending_contact_requests, get_sent_contact_requests, has_pending_contact_request,
    is_user_searchable, respond_to_contact_request,
};
use construct_server_shared::auth::AuthManager;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::db::DbPool;
use construct_server_shared::queue::MessageQueue;
use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    user_service_server::{UserService, UserServiceServer},
};
use construct_server_shared::user_service::UserServiceContext;
use serde_json::json;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct UserGrpcService {
    context: Arc<UserServiceContext>,
    /// gRPC client for notification-service — used to send silent push to User A on acceptance.
    notification_client: Option<NotificationClient>,
}

#[tonic::async_trait]
impl UserService for UserGrpcService {
    async fn get_user_profile(
        &self,
        request: Request<proto::GetUserProfileRequest>,
    ) -> Result<Response<proto::GetUserProfileResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let user = construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        Ok(Response::new(proto::GetUserProfileResponse {
            profile: Some(proto::UserProfile {
                user_id: user.id.to_string(),
                username: None, // server no longer stores plaintext username
                display_name: None,
                bio: None,
                profile_picture_url: None,
                email: None,
                phone: None,
                created_at: 0,
                last_seen: None,
                public_key_fingerprint: None,
                privacy: None,
                verified: false,
            }),
        }))
    }

    async fn update_user_profile(
        &self,
        request: Request<proto::UpdateUserProfileRequest>,
    ) -> Result<Response<proto::UpdateUserProfileResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let normalized_username = req.username.and_then(|u| {
            let trimmed = u.trim().to_lowercase();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        if let Some(ref username) = normalized_username {
            if username.len() < 3 || username.len() > 20 {
                return Err(Status::invalid_argument("username must be 3-20 characters"));
            }
            if !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(Status::invalid_argument(
                    "username can only contain letters, numbers, and underscores",
                ));
            }

            let secret = &self.context.config.security.username_hmac_secret;
            let hash = hash_username(secret, username);
            if let Some(existing) =
                construct_server_shared::db::get_user_by_username_hash(&self.context.db_pool, &hash)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                && existing.id != user_id
            {
                return Err(Status::already_exists("username is already taken"));
            }
        }

        let username_hash_opt: Option<Vec<u8>> = normalized_username.as_ref().map(|u| {
            let secret = &self.context.config.security.username_hmac_secret;
            hash_username(secret, u)
        });

        let updated = construct_server_shared::db::update_user_username(
            &self.context.db_pool,
            &user_id,
            username_hash_opt.as_deref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::UpdateUserProfileResponse {
            profile: Some(proto::UserProfile {
                user_id: updated.id.to_string(),
                username: None, // server no longer stores plaintext username
                display_name: None,
                bio: None,
                profile_picture_url: None,
                email: None,
                phone: None,
                created_at: 0,
                last_seen: None,
                public_key_fingerprint: None,
                privacy: None,
                verified: false,
            }),
        }))
    }

    async fn update_profile_picture(
        &self,
        _request: Request<proto::UpdateProfilePictureRequest>,
    ) -> Result<Response<proto::UpdateProfilePictureResponse>, Status> {
        Err(Status::unimplemented(
            "update_profile_picture is not implemented yet",
        ))
    }

    async fn get_user_capabilities(
        &self,
        request: Request<proto::GetUserCapabilitiesRequest>,
    ) -> Result<Response<proto::GetUserCapabilitiesResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let caps = db_agility::get_user_capabilities(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        let crypto_suites: Vec<String> = caps
            .crypto_suites
            .iter()
            .map(|suite| format!("{:?}", suite))
            .collect();
        let supports_pq = crypto_suites
            .iter()
            .any(|suite| suite.contains("Hybrid") || suite.contains("Kyber"));

        Ok(Response::new(proto::GetUserCapabilitiesResponse {
            user_id: caps.user_id.to_string(),
            crypto_suites,
            supports_webrtc: false,
            supports_mls: false,
            supports_pq,
            device_capabilities: vec![],
        }))
    }

    async fn block_user(
        &self,
        request: Request<proto::BlockUserRequest>,
    ) -> Result<Response<proto::BlockUserResponse>, Status> {
        let req = request.into_inner();
        let blocker_user_id = uuid::Uuid::parse_str(&req.blocker_user_id)
            .map_err(|_| Status::invalid_argument("invalid blocker_user_id"))?;
        let blocked_user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        if blocker_user_id == blocked_user_id {
            return Err(Status::invalid_argument("cannot block self"));
        }

        if construct_server_shared::db::get_user_by_id(&self.context.db_pool, &blocked_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .is_none()
        {
            return Err(Status::not_found("user not found"));
        }

        let blocked_at = construct_server_shared::db::block_user(
            &self.context.db_pool,
            &blocker_user_id,
            &blocked_user_id,
            req.reason.as_deref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::BlockUserResponse {
            success: true,
            blocked_at: blocked_at.timestamp_millis(),
        }))
    }

    async fn unblock_user(
        &self,
        request: Request<proto::UnblockUserRequest>,
    ) -> Result<Response<proto::UnblockUserResponse>, Status> {
        let req = request.into_inner();
        let blocker_user_id = uuid::Uuid::parse_str(&req.blocker_user_id)
            .map_err(|_| Status::invalid_argument("invalid blocker_user_id"))?;
        let blocked_user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let success = construct_server_shared::db::unblock_user(
            &self.context.db_pool,
            &blocker_user_id,
            &blocked_user_id,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::UnblockUserResponse { success }))
    }

    async fn get_blocked_users(
        &self,
        request: Request<proto::GetBlockedUsersRequest>,
    ) -> Result<Response<proto::GetBlockedUsersResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let blocked_users =
            construct_server_shared::db::get_blocked_users(&self.context.db_pool, &user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        let total_count = blocked_users.len() as u32;
        let blocked_users = blocked_users
            .into_iter()
            .map(|u| proto::BlockedUser {
                user_id: u.user_id.to_string(),
                username: String::new(), // server no longer stores plaintext username
                blocked_at: u.blocked_at.timestamp_millis(),
                reason: u.reason,
            })
            .collect();

        Ok(Response::new(proto::GetBlockedUsersResponse {
            blocked_users,
            total_count,
            next_cursor: None,
            has_more: false,
        }))
    }

    async fn delete_account(
        &self,
        request: Request<proto::DeleteAccountRequest>,
    ) -> Result<Response<proto::DeleteAccountResponse>, Status> {
        // Extract authenticated user_id from gRPC metadata (set by auth interceptor)
        let user_id_str = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("Missing x-user-id"))?
            .to_string();

        let user_id = uuid::Uuid::parse_str(&user_id_str)
            .map_err(|_| Status::invalid_argument("invalid user_id in metadata"))?;

        let req = request.into_inner();

        // Require confirmation string to prevent accidental deletion
        if req.confirmation.trim().to_uppercase() != "DELETE" {
            return Err(Status::invalid_argument(
                "confirmation must be 'DELETE' to proceed with account deletion",
            ));
        }

        // 1. Verify user exists
        construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        // 2. Revoke all active sessions and refresh tokens in Redis
        {
            let mut queue = self.context.queue.lock().await;
            if let Err(e) = queue.revoke_all_user_tokens(&user_id_str).await {
                tracing::warn!(
                    user_id = %user_id_str,
                    error = %e,
                    "Failed to revoke Redis tokens during account deletion (continuing)"
                );
            }
        }

        // 3. Delete user from DB — cascades to: devices, prekeys, blocked_users, invites, etc.
        construct_server_shared::db::delete_user_account(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete account: {}", e)))?;

        tracing::info!(
            target: "audit",
            event_type = "ACCOUNT_DELETION",
            user_id = %user_id_str,
            reason = req.reason.as_deref().unwrap_or("user_request"),
            "GDPR: Account deleted"
        );

        Ok(Response::new(proto::DeleteAccountResponse {
            success: true,
            message: "Account and all associated data have been permanently deleted.".to_string(),
            scheduled_deletion_at: None,
        }))
    }

    async fn export_user_data(
        &self,
        request: Request<proto::ExportUserDataRequest>,
    ) -> Result<Response<proto::ExportUserDataResponse>, Status> {
        // Extract authenticated user_id from gRPC metadata
        let user_id_str = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("Missing x-user-id"))?
            .to_string();

        let user_id = uuid::Uuid::parse_str(&user_id_str)
            .map_err(|_| Status::invalid_argument("invalid user_id in metadata"))?;

        // Fetch user profile
        let user = construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        // Fetch active devices
        let devices =
            construct_server_shared::db::get_devices_by_user_id(&self.context.db_pool, &user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        let device_list: Vec<serde_json::Value> = devices
            .iter()
            .map(|d| {
                json!({
                    "device_id": d.device_id,
                    "registered_at": d.registered_at.to_rfc3339(),
                    "is_active": d.is_active,
                })
            })
            .collect();

        // NOTE: Message content is NOT stored on the server (privacy-first design).
        // This export contains only account metadata.
        let export_data = json!({
            "export_version": "1.0",
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "data_notice": "Construct is a privacy-first messenger. Message content is never stored on the server. This export contains only your account metadata.",
            "profile": {
                "user_id": user.id.to_string(),
                "username": null, // server no longer stores plaintext username
                "account_created": null,
            },
            "devices": device_list,
        });

        tracing::info!(
            target: "audit",
            event_type = "DATA_EXPORT",
            user_id = %user_id_str,
            "GDPR: User data exported"
        );

        Ok(Response::new(proto::ExportUserDataResponse {
            data: export_data.to_string(),
            format: "json".to_string(),
            exported_at: chrono::Utc::now().timestamp_millis(),
        }))
    }

    async fn check_username_availability(
        &self,
        request: Request<proto::CheckUsernameAvailabilityRequest>,
    ) -> Result<Response<proto::CheckUsernameAvailabilityResponse>, Status> {
        let req = request.into_inner();
        if req.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        let normalized = req.username.to_lowercase();

        // Basic format validation (3-30 chars, ASCII alphanumeric + underscores only)
        // ASCII-only prevents homograph attacks (Cyrillic/Greek lookalikes)
        let valid_format = normalized.len() >= 3
            && normalized.len() <= 30
            && normalized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');

        if !valid_format {
            return Ok(Response::new(proto::CheckUsernameAvailabilityResponse {
                available: false,
                reason: Some("invalid_format".to_string()),
            }));
        }

        use construct_server_shared::db;
        let secret = &self.context.config.security.username_hmac_secret;
        let hash = hash_username(secret, &normalized);
        match db::get_user_by_username_hash(&self.context.db_pool, &hash).await {
            Ok(None) => Ok(Response::new(proto::CheckUsernameAvailabilityResponse {
                available: true,
                reason: None,
            })),
            Ok(Some(_)) => Ok(Response::new(proto::CheckUsernameAvailabilityResponse {
                available: false,
                reason: Some("taken".to_string()),
            })),
            Err(e) => Err(Status::internal(format!("Database error: {}", e))),
        }
    }

    async fn set_discoverable(
        &self,
        request: Request<proto::SetDiscoverableRequest>,
    ) -> Result<Response<proto::SetDiscoverableResponse>, Status> {
        // Auth: extract user_id from Envoy-injected metadata header.
        let user_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))?;

        let discoverable = request.into_inner().discoverable;

        // When opting in, verify the user actually has a username set.
        if discoverable {
            use construct_server_shared::db;
            let user = db::get_user_by_id(&self.context.db_pool, &user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::not_found("user not found"))?;

            if user.username_hash.is_none() {
                return Err(Status::failed_precondition(
                    "A username must be set before enabling discoverability",
                ));
            }
        }

        use construct_server_shared::db;
        db::set_user_searchable(&self.context.db_pool, &user_id, discoverable)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        tracing::info!(
            user_id = %user_id,
            discoverable = discoverable,
            "User updated discoverability setting"
        );

        Ok(Response::new(proto::SetDiscoverableResponse {
            discoverable,
        }))
    }

    async fn find_user(
        &self,
        request: Request<proto::FindUserRequest>,
    ) -> Result<Response<proto::FindUserResponse>, Status> {
        // Auth: must be authenticated to search.
        let caller_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))?;

        let req = request.into_inner();
        if req.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        // Rate limit: 5 searches per hour per caller (keyed by user_id to prevent
        // multi-account scraping through IP rotation — also add IP limit if needed).
        const MAX_SEARCHES_PER_HOUR: i64 = 5;
        const WINDOW_SECONDS: i64 = 3600;
        let rate_key = format!("rate:find_user:{}:hour", caller_id);
        {
            let mut queue = self.context.queue.lock().await;
            let count = queue
                .increment_rate_limit(&rate_key, WINDOW_SECONDS)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if count > MAX_SEARCHES_PER_HOUR {
                return Err(Status::resource_exhausted(
                    "Search rate limit exceeded. Try again later.",
                ));
            }
        }

        let normalized = req.username.trim().to_lowercase();
        let valid_format = normalized.len() >= 3
            && normalized.len() <= 30
            && normalized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_format {
            // Return not_found (not invalid_argument) to avoid leaking format oracle.
            return Err(Status::not_found("user not found"));
        }

        let secret = &self.context.config.security.username_hmac_secret;
        let hash = hash_username(secret, &normalized);

        use construct_server_shared::db;
        match db::find_discoverable_user_by_username_hash(&self.context.db_pool, &hash).await {
            Ok(Some(found_id)) => Ok(Response::new(proto::FindUserResponse {
                user_id: found_id.to_string(),
            })),
            // Identical response for "not found" and "not discoverable" — prevents oracle.
            Ok(None) => Err(Status::not_found("user not found")),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn send_contact_request(
        &self,
        request: Request<proto::SendContactRequestRequest>,
    ) -> Result<Response<proto::SendContactRequestResponse>, Status> {
        let caller_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))?;

        let req = request.into_inner();
        let to_user_id = uuid::Uuid::parse_str(&req.to_user_id)
            .map_err(|_| Status::invalid_argument("Invalid to_user_id"))?;

        if caller_id == to_user_id {
            return Err(Status::invalid_argument("Cannot send request to yourself"));
        }

        // Rate limit: 5 contact requests per day per sender.
        const MAX_REQUESTS_PER_DAY: i64 = 5;
        const WINDOW_SECONDS: i64 = 86400;
        let rate_key = format!("rate:contact_request:{}:day", caller_id);
        {
            let mut queue = self.context.queue.lock().await;
            let count = queue
                .increment_rate_limit(&rate_key, WINDOW_SECONDS)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if count > MAX_REQUESTS_PER_DAY {
                return Err(Status::resource_exhausted(
                    "Contact request rate limit exceeded. Try again later.",
                ));
            }
        }

        // Verify recipient is discoverable (searchable flag).
        let searchable = is_user_searchable(&self.context.db_pool, &to_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if !searchable {
            // Return not_found to avoid leaking discoverability status.
            return Err(Status::not_found("user not found"));
        }

        // Check that caller is not blocked by recipient.
        use construct_server_shared::db;
        let is_blocked = db::is_blocked_by(&self.context.db_pool, &to_user_id, &caller_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if is_blocked {
            return Err(Status::not_found("user not found"));
        }

        // Check for duplicate pending request (idempotent response for client retries).
        let sec = &self.context.config.security;
        let already_pending = has_pending_contact_request(
            &self.context.db_pool,
            caller_id,
            to_user_id,
            &sec.contact_hmac_secret,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if already_pending {
            return Ok(Response::new(proto::SendContactRequestResponse {
                request_id: String::new(),
                status: proto::ContactRequestStatus::Pending as i32,
            }));
        }

        let request_id = create_contact_request(
            &self.context.db_pool,
            caller_id,
            to_user_id,
            &sec.contact_hmac_secret,
            &sec.request_envelope_key,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::SendContactRequestResponse {
            request_id: request_id.to_string(),
            status: proto::ContactRequestStatus::Pending as i32,
        }))
    }

    async fn get_contact_requests(
        &self,
        request: Request<proto::GetContactRequestsRequest>,
    ) -> Result<Response<proto::GetContactRequestsResponse>, Status> {
        let caller_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))?;

        let sec = &self.context.config.security;

        let incoming_raw = get_pending_contact_requests(
            &self.context.db_pool,
            caller_id,
            &sec.contact_hmac_secret,
            &sec.request_envelope_key,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let mut incoming = Vec::with_capacity(incoming_raw.len());
        for cr in incoming_raw {
            // Server is privacy-preserving: display_name and plaintext username are not stored.
            // The client resolves display info from its local cache or via key bundle.
            incoming.push(proto::IncomingContactRequest {
                request_id: cr.id.to_string(),
                from_user_id: cr.from_user_id.to_string(),
                from_display_name: String::new(),
                from_username: String::new(),
                created_at: cr.created_at.timestamp(),
            });
        }

        let sent_raw =
            get_sent_contact_requests(&self.context.db_pool, caller_id, &sec.contact_hmac_secret)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        let sent = sent_raw
            .into_iter()
            .map(|cr| proto::SentContactRequest {
                request_id: cr.id.to_string(),
                status: match cr.status.as_str() {
                    "accepted" => proto::ContactRequestStatus::Accepted as i32,
                    "declined_blocked" => proto::ContactRequestStatus::DeclinedBlocked as i32,
                    "spam_blocked" => proto::ContactRequestStatus::SpamBlocked as i32,
                    _ => proto::ContactRequestStatus::Pending as i32,
                },
                created_at: cr.created_at.timestamp(),
            })
            .collect();

        Ok(Response::new(proto::GetContactRequestsResponse {
            incoming,
            sent,
        }))
    }

    async fn respond_to_contact_request(
        &self,
        request: Request<proto::RespondToContactRequestRequest>,
    ) -> Result<Response<proto::RespondToContactRequestResponse>, Status> {
        let caller_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))?;

        let req = request.into_inner();
        let request_id = uuid::Uuid::parse_str(&req.request_id)
            .map_err(|_| Status::invalid_argument("Invalid request_id"))?;

        let action = proto::ContactRequestAction::try_from(req.action)
            .map_err(|_| Status::invalid_argument("Invalid action"))?;

        let db_status = match action {
            proto::ContactRequestAction::Accept => "accepted",
            proto::ContactRequestAction::DeclineBlock => "declined_blocked",
            proto::ContactRequestAction::SpamBlock => "spam_blocked",
            proto::ContactRequestAction::Unspecified => {
                return Err(Status::invalid_argument("Action must be specified"));
            }
        };

        let sec = &self.context.config.security;

        // Get sender ID before updating status (needed for accept flow).
        let from_user_id = if action == proto::ContactRequestAction::Accept {
            Some(
                get_contact_request_sender(
                    &self.context.db_pool,
                    request_id,
                    caller_id,
                    &sec.contact_hmac_secret,
                    &sec.request_envelope_key,
                )
                .await
                .map_err(|e| Status::not_found(e.to_string()))?,
            )
        } else {
            None
        };

        respond_to_contact_request(
            &self.context.db_pool,
            request_id,
            caller_id,
            db_status,
            &sec.contact_hmac_secret,
        )
        .await
        .map_err(|e| Status::not_found(e.to_string()))?;

        use construct_crypto::hmac_sha256;
        use construct_server_shared::db;

        if action == proto::ContactRequestAction::Accept {
            if let Some(sender_id) = from_user_id {
                let caller_hmac = hmac_sha256(&sec.contact_hmac_secret, caller_id.as_bytes());
                let sender_hmac = hmac_sha256(&sec.contact_hmac_secret, sender_id.as_bytes());
                db::add_contact_link(&self.context.db_pool, &caller_hmac, &sender_hmac)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                db::add_contact_link(&self.context.db_pool, &sender_hmac, &caller_hmac)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;

                // Phase 2: silent push to User A (sender) so they discover acceptance
                // without waiting for the next time they open the Synaps tab.
                if let Some(notification_client) = &self.notification_client
                    && !notification_client.is_circuit_open()
                {
                    let mut notif = notification_client.get();
                    let push_req = proto::SendBlindNotificationRequest {
                        user_id: sender_id.to_string(),
                        badge_count: None,
                        activity_type: Some("contact_request_accepted".to_string()),
                        conversation_id: Some(req.request_id.clone()),
                    };
                    match notif.send_blind_notification(push_req).await {
                        Ok(_) => {
                            notification_client.record_success();
                            tracing::info!(
                                to_user = %sender_id,
                                request_id = %req.request_id,
                                "Sent contact_request_accepted push to User A"
                            );
                        }
                        Err(e) => {
                            notification_client.record_failure();
                            tracing::warn!(
                                error = %e,
                                to_user = %sender_id,
                                "Failed to send contact_request_accepted push — User A will discover via polling"
                            );
                        }
                    }
                }
            }
        } else {
            // Block/spam: add block entry.
            // We decrypt from_enc to get sender_id for blocking.
            let sender_id = get_contact_request_sender(
                &self.context.db_pool,
                request_id,
                caller_id,
                &sec.contact_hmac_secret,
                &sec.request_envelope_key,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

            db::block_user(&self.context.db_pool, &caller_id, &sender_id, None)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        Ok(Response::new(proto::RespondToContactRequestResponse {
            status: match action {
                proto::ContactRequestAction::Accept => proto::ContactRequestStatus::Accepted,
                proto::ContactRequestAction::DeclineBlock => {
                    proto::ContactRequestStatus::DeclinedBlocked
                }
                proto::ContactRequestAction::SpamBlock => proto::ContactRequestStatus::SpamBlocked,
                proto::ContactRequestAction::Unspecified => unreachable!("already handled above"),
            } as i32,
        }))
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== User Service Starting ===");
    info!("Port: {}", config.port);

    // Initialize database
    info!("Connecting to database...");
    let db_pool = Arc::new(
        DbPool::connect(&config.database_url)
            .await
            .context("Failed to connect to database")?,
    );
    info!("Connected to database");

    // Apply database migrations
    info!("Applying database migrations...");
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await
        .context("Failed to apply database migrations")?;
    info!("Database migrations applied successfully");

    // Initialize Redis
    info!("Connecting to Redis...");
    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .context("Failed to create message queue")?,
    ));
    info!("Connected to Redis");

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // Create notification-service gRPC client for contact_request_accepted push.
    let url = env::var("NOTIFICATION_SERVICE_URL")
        .unwrap_or_else(|_| "http://notification:50054".to_string());
    let notification_client = match NotificationClient::new(&url) {
        Ok(client) => {
            info!(url = %url, "Notification service gRPC client initialized (user-service)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create notification gRPC client — contact-accepted push disabled");
            None
        }
    };

    let context = Arc::new(UserServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
    });

    // handlers module is local (user-service/src/handlers.rs)

    // Start gRPC UserService (SVC-2 scaffold)
    let grpc_context = context.clone();
    let grpc_notification_client = notification_client.clone();
    let grpc_bind_address =
        env::var("USER_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50052".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_address).await?;
    // Replace bare .serve() with graceful shutdown for gRPC
    let grpc_keepalive_secs = config.grpc_keepalive_interval_secs;
    let grpc_keepalive_timeout_secs = config.grpc_keepalive_timeout_secs;
    tokio::spawn(async move {
        let service = UserGrpcService {
            context: grpc_context,
            notification_client: grpc_notification_client,
        };
        if let Err(e) =
            construct_server_shared::grpc_server(grpc_keepalive_secs, grpc_keepalive_timeout_secs)
                .add_service(UserServiceServer::new(service))
                .serve_with_incoming_shutdown(
                    grpc_incoming,
                    construct_server_shared::shutdown_signal(),
                )
                .await
        {
            tracing::error!(error = %e, "User gRPC server failed");
        }
    });
    info!("User gRPC listening on {}", grpc_bind_address);

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        )
        // Device-signed account deletion (Phase 5.0.1)
        .route(
            "/api/v1/users/me/delete-challenge",
            get(handlers::get_delete_challenge),
        )
        .route(
            "/api/v1/users/me/delete-confirm",
            post(handlers::confirm_delete),
        )
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("User Service listening on {}", config.bind_address);

    let listener = construct_server_shared::mptcp_or_tcp_listener(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start server")?;

    Ok(())
}
