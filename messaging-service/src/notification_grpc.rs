use std::sync::Arc;

use construct_server_shared::auth_utils;
use construct_server_shared::shared::proto::services::v1 as proto;
use construct_server_shared::shared::proto::signaling::v1::CallType as SignalingCallType;
use proto::notification_service_server::NotificationService;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::context::MessagingServiceContext;
use crate::notification_core;

/// gRPC implementation of NotificationService — runs on messaging's gRPC port
pub struct NotificationGrpcService {
    pub context: Arc<MessagingServiceContext>,
}

impl NotificationGrpcService {
    fn notif_ctx(
        &self,
    ) -> Result<
        &Arc<construct_server_shared::notification_service::NotificationServiceContext>,
        Status,
    > {
        self.context.notification_context.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "Notification service not initialized (APNs not configured)",
            )
        })
    }
}

#[tonic::async_trait]
impl NotificationService for NotificationGrpcService {
    async fn send_blind_notification(
        &self,
        request: Request<proto::SendBlindNotificationRequest>,
    ) -> Result<Response<proto::SendBlindNotificationResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id"))?;

        let input = notification_core::SendBlindNotificationInput {
            user_id,
            badge_count: req.badge_count,
            activity_type: req.activity_type,
            conversation_id: req.conversation_id,
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::send_blind_notification(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to send notification: {}", e)))?;

        Ok(Response::new(proto::SendBlindNotificationResponse {
            success: output.success,
        }))
    }

    async fn register_device_token(
        &self,
        request: Request<proto::RegisterDeviceTokenRequest>,
    ) -> Result<Response<proto::RegisterDeviceTokenResponse>, Status> {
        let user_id = auth_utils::extract_user_id(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let input = notification_core::RegisterDeviceTokenInput {
            user_id,
            device_token: req.device_token,
            device_name: req.device_name,
            notification_filter: req.notification_filter,
            device_id: if req.device_id.is_empty() {
                None
            } else {
                Some(req.device_id)
            },
            push_provider: match req.provider {
                2 => "fcm".to_string(),
                _ => "apns".to_string(),
            },
            push_environment: match req.environment {
                2 => "production".to_string(),
                _ => "sandbox".to_string(),
            },
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::register_device_token(ctx, input)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to register device token");
                Status::internal(format!("Failed to register device token: {}", e))
            })?;

        Ok(Response::new(proto::RegisterDeviceTokenResponse {
            success: output.success,
            token_id: output.token_id,
        }))
    }

    async fn unregister_device_token(
        &self,
        request: Request<proto::UnregisterDeviceTokenRequest>,
    ) -> Result<Response<proto::UnregisterDeviceTokenResponse>, Status> {
        let user_id = auth_utils::extract_user_id(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let input = notification_core::UnregisterDeviceTokenInput {
            user_id,
            device_token: req.device_token,
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::unregister_device_token(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to unregister device token: {}", e)))?;

        Ok(Response::new(proto::UnregisterDeviceTokenResponse {
            success: output.success,
        }))
    }

    async fn update_notification_preferences(
        &self,
        request: Request<proto::UpdateNotificationPreferencesRequest>,
    ) -> Result<Response<proto::UpdateNotificationPreferencesResponse>, Status> {
        let user_id = auth_utils::extract_user_id(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let input = notification_core::UpdateNotificationPreferencesInput {
            user_id,
            device_token: req.device_token,
            notification_filter: req.notification_filter,
            enabled: req.enabled,
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::update_notification_preferences(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to update preferences: {}", e)))?;

        Ok(Response::new(
            proto::UpdateNotificationPreferencesResponse {
                success: output.success,
            },
        ))
    }

    async fn register_voip_token(
        &self,
        request: Request<proto::RegisterVoipTokenRequest>,
    ) -> Result<Response<proto::RegisterVoipTokenResponse>, Status> {
        let user_id = auth_utils::extract_user_id(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let input = notification_core::RegisterVoipTokenInput {
            user_id,
            voip_token: req.voip_token,
            device_id: req.device_id,
            platform: req.platform,
            push_environment: match req.environment {
                2 => "production".to_string(),
                _ => "sandbox".to_string(),
            },
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::register_voip_token(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to register voip token: {}", e)))?;

        Ok(Response::new(proto::RegisterVoipTokenResponse {
            success: output.success,
        }))
    }

    async fn unregister_voip_token(
        &self,
        request: Request<proto::UnregisterVoipTokenRequest>,
    ) -> Result<Response<proto::UnregisterVoipTokenResponse>, Status> {
        let user_id = auth_utils::extract_user_id(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let input = notification_core::UnregisterVoipTokenInput {
            user_id,
            device_id: req.device_id,
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::unregister_voip_token(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to unregister voip token: {}", e)))?;

        Ok(Response::new(proto::UnregisterVoipTokenResponse {
            success: output.success,
        }))
    }

    async fn send_voip_incoming_call(
        &self,
        request: Request<proto::SendVoipIncomingCallRequest>,
    ) -> Result<Response<proto::SendVoipIncomingCallResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id"))?;

        let call_type_str = match req.call_type() {
            SignalingCallType::Audio => "audio",
            SignalingCallType::Video => "video",
            SignalingCallType::Screen => "screen",
            SignalingCallType::Group => "group",
            SignalingCallType::Unspecified => {
                return Err(Status::invalid_argument("call_type is required"));
            }
        }
        .to_string();

        let input = notification_core::SendVoipIncomingCallInput {
            user_id,
            call_id: req.call_id,
            caller_id: req.caller_id,
            caller_name: req.caller_name,
            call_type: call_type_str,
            offered_at: req.offered_at,
        };

        let ctx = self.notif_ctx()?;
        let output = notification_core::send_voip_incoming_call(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to send VoIP incoming call: {}", e)))?;

        Ok(Response::new(proto::SendVoipIncomingCallResponse {
            success: output.success,
            sent_count: output.sent_count,
        }))
    }

    async fn send_key_rotation_wake(
        &self,
        request: Request<proto::SendKeyRotationWakeRequest>,
    ) -> Result<Response<proto::SendKeyRotationWakeResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id"))?;

        let input = notification_core::SendKeyRotationWakeInput { user_id };

        let ctx = self.notif_ctx()?;
        let output = notification_core::send_key_rotation_wake(ctx, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to send key rotation wake: {}", e)))?;

        Ok(Response::new(proto::SendKeyRotationWakeResponse {
            success: output.success,
        }))
    }
}
