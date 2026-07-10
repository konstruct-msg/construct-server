// ============================================================================
// Identity Service — merged auth + user + invite (Phase 2.7)
// ============================================================================
//
// gRPC services (all on port 50051):
//   AuthService, DeviceService, DeviceLinkService  ← from auth-service
//   UserService, InviteService                     ← from user-service
//
// HTTP (port 8081):
//   /api/v1/auth/*             — auth endpoints
//   /api/v1/users/me/delete-*  — device-signed account deletion
//   /.well-known/*, /jwks.json — discovery + JWKS
// ============================================================================

mod context;
mod invite_core;
mod recovery;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose as b64};
use construct_config::Config;
use construct_server_shared::{
    auth_service::AuthServiceContext, db::DbPool, queue::MessageQueue,
    user_service::UserServiceContext,
};
use context::IdentityServiceContext;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, sync::Arc};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use x25519_dalek::PublicKey as X25519PublicKey;

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    auth_service_server::{AuthService, AuthServiceServer},
    device_link_service_server::DeviceLinkServiceServer,
    device_service_server::DeviceServiceServer,
    invite_service_server::{InviteService, InviteServiceServer},
    user_service_server::{UserService, UserServiceServer},
};

// ============================================================================
// gRPC service struct
// ============================================================================

#[derive(Clone)]
struct IdentityGrpcService {
    context: Arc<IdentityServiceContext>,
    veil_bridge_cert: Option<String>,
    token_issuer_key: Option<[u8; 32]>,
    /// Signs `SenderCertificate` (`BUNDLE_SIGNING_KEY`, same secret key-service
    /// signs prekey bundles / KT tree heads with). Clients verify certificates
    /// against `bundle_verification_key` from well-known, so certs must be
    /// signed by this key — NOT the federation signer (`SERVER_SIGNING_KEY`),
    /// whose public half clients never see. Falls back to the federation
    /// signer when unset (single-key dev setups).
    cert_signing_key: Option<ed25519_dalek::SigningKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JoinRequestData {
    pending_device_id: String,
    identity_public_b64: String,
    verifying_key_b64: String,
    signed_prekey_public_b64: String,
    signed_prekey_signature_b64: String,
    device_name: String,
    platform: String,
}

fn app_error_to_status(e: construct_error::AppError) -> Status {
    use construct_error::AppError;
    match &e {
        AppError::Auth(msg) => Status::unauthenticated(msg.clone()),
        AppError::Validation(msg) => Status::invalid_argument(msg.clone()),
        AppError::NotFound(msg) => Status::not_found(msg.clone()),
        AppError::TooManyRequests(msg) => Status::resource_exhausted(msg.clone()),
        AppError::Forbidden(msg) => Status::permission_denied(msg.clone()),
        AppError::Conflict(msg) => Status::already_exists(msg.clone()),
        AppError::Jwt(_) => Status::unauthenticated("Invalid or expired token".to_string()),
        _ => Status::internal(e.to_string()),
    }
}

fn request_token(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
    let auth = metadata
        .get("authorization")
        .or_else(|| metadata.get("Authorization"))
        .ok_or_else(|| Status::unauthenticated("missing authorization header"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization header"))?;

    auth.strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("authorization must be Bearer token"))
}

/// Canonical `SenderCertificate.server_signature` payload — stealth-sealed-sender-v2
/// Phase 3: direct concatenation, no separators, `issued_at`/`expires_at` as raw
/// big-endian 8-byte integers. Must match the iOS client's
/// `StealthSenderService.buildCertPayload` exactly.
fn build_sender_cert_sign_payload(
    user_id: &str,
    domain: &str,
    identity_key: &[u8],
    device_id: &str,
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(user_id.as_bytes());
    payload.extend_from_slice(domain.as_bytes());
    payload.extend_from_slice(identity_key);
    payload.extend_from_slice(device_id.as_bytes());
    payload.extend_from_slice(&issued_at.to_be_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
    payload
}

fn extract_user_id_from_metadata(
    auth_manager: &Arc<construct_server_shared::auth::AuthManager>,
    metadata: &tonic::metadata::MetadataMap,
) -> Result<uuid::Uuid, Status> {
    construct_server_shared::auth_utils::extract_user_id(auth_manager, metadata)
}

// ============================================================================
// AuthService implementation
// ============================================================================

#[tonic::async_trait]
impl AuthService for IdentityGrpcService {
    async fn get_pow_challenge(
        &self,
        _request: Request<proto::GetPowChallengeRequest>,
    ) -> Result<Response<proto::GetPowChallengeResponse>, Status> {
        let app_context = Arc::new(self.context.to_app_context());
        let axum::Json(challenge) = construct_server_shared::auth_service::core::get_pow_challenge(
            app_context,
            axum::http::HeaderMap::new(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .1;
        Ok(Response::new(proto::GetPowChallengeResponse {
            challenge: challenge.challenge,
            difficulty: challenge.difficulty,
            expires_at: challenge.expires_at,
        }))
    }

    async fn register_device(
        &self,
        request: Request<proto::RegisterDeviceRequest>,
    ) -> Result<Response<proto::RegisterDeviceResponse>, Status> {
        let req = request.into_inner();
        let public_keys = req
            .public_keys
            .ok_or_else(|| Status::invalid_argument("public_keys is required"))?;
        let pow_solution = req
            .pow_solution
            .ok_or_else(|| Status::invalid_argument("pow_solution is required"))?;
        let app_context = Arc::new(self.context.to_app_context());
        let (_status, axum::Json(response)) =
            construct_server_shared::auth_service::core::register_device(
                app_context,
                axum::http::HeaderMap::new(),
                construct_server_shared::auth_service::core::RegisterDeviceInput {
                    username: req.username,
                    device_id: req.device_id,
                    public_keys:
                        construct_server_shared::auth_service::core::DevicePublicKeysInput {
                            verifying_key: public_keys.verifying_key,
                            identity_public: public_keys.identity_public,
                            signed_prekey_public: public_keys.signed_prekey_public,
                            signed_prekey_signature: public_keys.signed_prekey_signature,
                            crypto_suite: public_keys.crypto_suite,
                            supports_pq_ratchet: public_keys.supports_pq_ratchet,
                        },
                    pow_solution: construct_server_shared::auth_service::core::PowSolutionInput {
                        challenge: pow_solution.challenge,
                        nonce: pow_solution.nonce,
                        hash: pow_solution.hash,
                    },
                    identity_public_key: req.identity_public_key,
                    identity_key_type: req.identity_key_type,
                },
            )
            .await
            .map_err(app_error_to_status)?;

        Ok(Response::new(proto::RegisterDeviceResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: response.user_id,
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
                veil_bridge_cert: self.veil_bridge_cert.clone(),
            }),
        }))
    }

    async fn authenticate_device(
        &self,
        request: Request<proto::AuthenticateDeviceRequest>,
    ) -> Result<Response<proto::AuthenticateDeviceResponse>, Status> {
        let req = request.into_inner();
        let app_context = Arc::new(self.context.to_app_context());
        let (_status, axum::Json(response)) =
            construct_server_shared::auth_service::core::authenticate_device(
                app_context,
                construct_server_shared::auth_service::core::AuthenticateDeviceInput {
                    device_id: req.device_id,
                    timestamp: req.timestamp,
                    signature: req.signature,
                },
            )
            .await
            .map_err(app_error_to_status)?;

        Ok(Response::new(proto::AuthenticateDeviceResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: response.user_id,
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
                veil_bridge_cert: self.veil_bridge_cert.clone(),
            }),
        }))
    }

    async fn refresh_token(
        &self,
        request: Request<proto::RefreshTokenRequest>,
    ) -> Result<Response<proto::RefreshTokenResponse>, Status> {
        let app_context = Arc::new(self.context.to_app_context());
        let response = construct_server_shared::auth_service::core::refresh_tokens_proto(
            app_context,
            request.into_inner(),
        )
        .await
        .map_err(app_error_to_status)?;
        Ok(Response::new(response))
    }

    async fn verify_token(
        &self,
        request: Request<proto::VerifyTokenRequest>,
    ) -> Result<Response<proto::VerifyTokenResponse>, Status> {
        let token = request.into_inner().access_token;
        let claims = match self.context.auth_manager.verify_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return Ok(Response::new(proto::VerifyTokenResponse {
                    valid: false,
                    user_id: None,
                    device_id: None,
                    expires_at: None,
                }));
            }
        };

        let invalidated = {
            let mut queue = self.context.queue.lock().await;
            match queue.is_token_invalidated(&claims.jti).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(error = %e, "Redis unavailable during token check — failing closed");
                    true
                }
            }
        };
        if invalidated {
            return Ok(Response::new(proto::VerifyTokenResponse {
                valid: false,
                user_id: None,
                device_id: None,
                expires_at: None,
            }));
        }

        Ok(Response::new(proto::VerifyTokenResponse {
            valid: true,
            user_id: Some(claims.sub),
            device_id: claims.device_id,
            expires_at: Some(claims.exp),
        }))
    }

    async fn logout(
        &self,
        request: Request<proto::LogoutRequest>,
    ) -> Result<Response<proto::LogoutResponse>, Status> {
        let req = request.into_inner();
        if req.access_token.is_empty() {
            return Err(Status::invalid_argument("access_token is required"));
        }
        let claims = self
            .context
            .auth_manager
            .verify_token(&req.access_token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::auth_service::core::logout_user(
            app_context,
            user_id,
            req.all_devices,
            Some(&claims.jti),
            Some(claims.exp),
            claims.device_id.as_deref(),
        )
        .await
        .map_err(app_error_to_status)?;

        Ok(Response::new(proto::LogoutResponse { success: true }))
    }

    async fn set_recovery_key(
        &self,
        request: Request<proto::SetRecoveryKeyRequest>,
    ) -> Result<Response<proto::SetRecoveryKeyResponse>, Status> {
        let token = request_token(request.metadata())?;
        let req = request.into_inner();

        if req.recovery_public_key.is_empty() {
            return Err(Status::invalid_argument("recovery_public_key is required"));
        }
        if req.setup_signature.is_empty() {
            return Err(Status::invalid_argument("setup_signature is required"));
        }
        if req.timestamp == 0 {
            return Err(Status::invalid_argument("timestamp is required"));
        }

        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let fingerprint = recovery::set_recovery_key(
            self.context.db_pool.as_ref(),
            user_id,
            &req.recovery_public_key,
            &req.setup_signature,
            req.timestamp,
            req.encrypted_backup.as_deref(),
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("already set") {
                Status::already_exists(msg)
            } else if msg.contains("expired") || msg.contains("Invalid") {
                Status::invalid_argument(msg)
            } else {
                Status::internal(msg)
            }
        })?;

        Ok(Response::new(proto::SetRecoveryKeyResponse {
            success: true,
            fingerprint,
            setup_at: chrono::Utc::now().timestamp(),
            error: None,
        }))
    }

    async fn get_recovery_status(
        &self,
        request: Request<proto::GetRecoveryStatusRequest>,
    ) -> Result<Response<proto::GetRecoveryStatusResponse>, Status> {
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let status = recovery::get_recovery_status(self.context.db_pool.as_ref(), user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::GetRecoveryStatusResponse {
            is_setup: status.is_setup,
            fingerprint: status.fingerprint,
            setup_at: status.setup_at.map(|t| t.timestamp()),
            last_used_at: status.last_used_at.map(|t| t.timestamp()),
            has_backup: status.has_backup,
        }))
    }

    async fn recover_account(
        &self,
        request: Request<proto::RecoverAccountRequest>,
    ) -> Result<Response<proto::RecoverAccountResponse>, Status> {
        let req = request.into_inner();

        if req.identifier.is_empty() {
            return Err(Status::invalid_argument("identifier is required"));
        }
        if req.challenge.is_empty() {
            return Err(Status::invalid_argument("challenge is required"));
        }
        if req.recovery_signature.is_empty() {
            return Err(Status::invalid_argument("recovery_signature is required"));
        }
        let new_device = req
            .new_device
            .ok_or_else(|| Status::invalid_argument("new_device is required"))?;
        let public_keys = new_device
            .public_keys
            .ok_or_else(|| Status::invalid_argument("new_device.public_keys is required"))?;

        let db = self.context.db_pool.as_ref();

        let user_id = recovery::verify_recovery_signature(
            db,
            &req.identifier,
            &req.challenge,
            &req.recovery_signature,
            &self.context.config.security.username_hmac_secret,
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                Status::not_found(msg)
            } else if msg.contains("not set up") {
                Status::failed_precondition(msg)
            } else if msg.contains("cooldown") {
                Status::resource_exhausted(msg)
            } else if msg.contains("Invalid") {
                Status::permission_denied(msg)
            } else {
                Status::internal(msg)
            }
        })?;

        let devices_revoked = recovery::revoke_all_devices(db, user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::auth_service::core::logout_user(
            app_context.clone(),
            user_id,
            true,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let hostname = env::var("SERVER_HOSTNAME").unwrap_or_else(|_| "construct.cc".to_string());
        let verifying_key = public_keys.verifying_key.clone();
        let signed_prekey_public = public_keys.signed_prekey_public.clone();
        let signed_prekey_signature = public_keys.signed_prekey_signature.clone();

        verify_spk_signature(
            &verifying_key,
            &signed_prekey_public,
            &signed_prekey_signature,
        )?;

        construct_server_shared::db::create_device(
            self.context.db_pool.as_ref(),
            construct_server_shared::db::CreateDeviceData {
                device_id: new_device.device_id.clone(),
                server_hostname: hostname,
                verifying_key,
                identity_public: public_keys.identity_public,
                signed_prekey_public,
                signed_prekey_signature,
                crypto_suites: format!(r#"["{}"]"#, public_keys.crypto_suite),
                supports_pq_ratchet: false,
            },
            Some(user_id),
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("IDENTITY_KEY_CONFLICT") {
                Status::already_exists("Identity key already registered by another device")
            } else {
                Status::internal(msg)
            }
        })?;

        let (access_token, _, exp_timestamp) = app_context
            .auth_manager
            .create_token_for_device(&user_id, Some(&new_device.device_id))
            .map_err(|e| Status::internal(e.to_string()))?;

        let (refresh_token, refresh_jti, _) = app_context
            .auth_manager
            .create_refresh_token_for_device(&user_id, Some(&new_device.device_id))
            .map_err(|e| Status::internal(e.to_string()))?;

        {
            let mut queue = app_context.queue.lock().await;
            let ttl = app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;
            if let Err(e) = queue
                .store_refresh_token(&refresh_jti, &user_id.to_string(), ttl)
                .await
            {
                tracing::warn!(error = %e, "Failed to store refresh token during recovery");
            }
        }

        recovery::mark_recovery_used(db, user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let now = chrono::Utc::now().timestamp();
        Ok(Response::new(proto::RecoverAccountResponse {
            success: true,
            user_id: user_id.to_string(),
            tokens: Some(proto::AuthTokensResponse {
                user_id: user_id.to_string(),
                access_token,
                refresh_token,
                expires_at: exp_timestamp,
                veil_bridge_cert: self.veil_bridge_cert.clone(),
            }),
            devices_revoked,
            recovered_at: now,
            warnings: vec!["All existing sessions have been terminated".to_string()],
            error: None,
        }))
    }

    async fn store_recovery_bundle(
        &self,
        request: Request<proto::StoreRecoveryBundleRequest>,
    ) -> Result<Response<proto::StoreRecoveryBundleResponse>, Status> {
        let token = request_token(request.metadata())?;
        let req = request.into_inner();

        if req.bundle_ciphertext.is_empty() {
            return Err(Status::invalid_argument("bundle_ciphertext is required"));
        }
        if req.bundle_ciphertext.len() > 4096 {
            return Err(Status::invalid_argument(
                "bundle_ciphertext exceeds maximum size of 4096 bytes",
            ));
        }

        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        sqlx::query(
            "UPDATE users SET social_recovery_bundle = $1, social_recovery_bundle_set_at = NOW() WHERE id = $2",
        )
        .bind(&req.bundle_ciphertext)
        .bind(user_id)
        .execute(self.context.db_pool.as_ref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::StoreRecoveryBundleResponse {
            success: true,
        }))
    }

    async fn get_recovery_bundle(
        &self,
        request: Request<proto::GetRecoveryBundleRequest>,
    ) -> Result<Response<proto::GetRecoveryBundleResponse>, Status> {
        let req = request.into_inner();
        if req.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        let hash = construct_crypto::hash_username(
            &self.context.config.security.username_hmac_secret,
            &req.username,
        );

        let row: Option<(Option<Vec<u8>>,)> =
            sqlx::query_as("SELECT social_recovery_bundle FROM users WHERE username_hash = $1")
                .bind(&hash)
                .fetch_optional(self.context.db_pool.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        match row {
            Some((Some(bundle),)) => Ok(Response::new(proto::GetRecoveryBundleResponse {
                bundle_ciphertext: bundle,
                bundle_exists: true,
            })),
            _ => Ok(Response::new(proto::GetRecoveryBundleResponse {
                bundle_ciphertext: vec![],
                bundle_exists: false,
            })),
        }
    }

    async fn get_sender_certificate(
        &self,
        request: Request<proto::GetSenderCertificateRequest>,
    ) -> Result<Response<proto::GetSenderCertificateResponse>, Status> {
        use construct_server_shared::shared::proto::core::v1::SenderCertificate;
        use prost::Message;

        // Fail closed (sealed-sender-resilience C′): sign ONLY with the dedicated bundle
        // key clients verify against. The old federation-signer fallback produced
        // certificates that were valid *only if* the federation key happened to equal the
        // published bundle_verification_key — a condition never checked, so on any real
        // deployment it silently yielded 100% unverifiable certs (dropped at every
        // recipient). Refusing here surfaces the misconfiguration at issuance (the client's
        // degraded-send path engages, counted) instead of downstream as silent message loss.
        if self.cert_signing_key.is_none() {
            return Err(Status::unavailable(
                "sealed sender not available: BUNDLE_SIGNING_KEY not configured — refusing \
                 to sign sender certificates with the federation signer (they would fail \
                 client verification against bundle_verification_key)",
            ));
        }

        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {}", e)))?;
        let user_id = &claims.sub;

        let device_id = request
            .metadata()
            .get("x-device-id")
            .ok_or_else(|| Status::invalid_argument("x-device-id header required"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("invalid x-device-id header"))?
            .to_string();

        let user_uuid = uuid::Uuid::parse_str(user_id)
            .map_err(|_| Status::internal("invalid user_id in token"))?;

        let identity_key: Vec<u8> = sqlx::query_scalar(
            "SELECT identity_public FROM devices WHERE user_id = $1 AND device_id = $2 AND is_active = true",
        )
        .bind(user_uuid)
        .bind(&device_id)
        .fetch_optional(self.context.db_pool.as_ref())
        .await
        .map_err(|e| Status::internal(format!("database error: {}", e)))?
        .ok_or_else(|| Status::not_found("device not found or inactive"))?;

        let now = chrono::Utc::now().timestamp();
        let expires_at = now + 86400;
        let domain = self.context.config.federation.instance_domain.clone();

        let sign_payload = build_sender_cert_sign_payload(
            user_id,
            &domain,
            &identity_key,
            &device_id,
            now,
            expires_at,
        );

        let signature = self
            .cert_signing_key
            .as_ref()
            .expect("checked above")
            .sign(&sign_payload)
            .to_bytes()
            .to_vec();
        let cert = SenderCertificate {
            sender_user_id: user_id.to_string(),
            sender_domain: domain,
            sender_identity_key: identity_key,
            sender_device_id: device_id,
            issued_at: now,
            expires_at,
            server_signature: signature,
        };

        tracing::info!(user_id = %user_id, expires_at = %expires_at, "Issued sender certificate");

        Ok(Response::new(proto::GetSenderCertificateResponse {
            certificate: cert.encode_to_vec(),
            expires_at,
        }))
    }

    async fn approve_join_request(
        &self,
        request: Request<proto::ApproveJoinRequestRequest>,
    ) -> Result<Response<proto::ApproveJoinRequestResponse>, Status> {
        let token = request_token(request.metadata())?;
        let req = request.into_inner();

        if req.pending_device_id.is_empty() {
            return Err(Status::invalid_argument("pending_device_id is required"));
        }

        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let json_payload = {
            let mut queue = self.context.queue.lock().await;
            queue
                .consume_join_request(&req.pending_device_id)
                .await
                .map_err(|e| Status::internal(format!("Redis error: {e}")))?
        }
        .ok_or_else(|| Status::not_found("join request not found or expired"))?;

        let join_data: JoinRequestData = serde_json::from_str(&json_payload)
            .map_err(|e| Status::internal(format!("invalid join request data: {e}")))?;

        if construct_db::device_exists(self.context.db_pool.as_ref(), &req.pending_device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::already_exists("device_id already registered"));
        }

        let b64_dec = base64::engine::general_purpose::STANDARD;
        let decode = |s: &str, field: &str| {
            b64_dec
                .decode(s)
                .map_err(|_| Status::invalid_argument(format!("invalid base64 in {field}")))
        };

        let verifying_key = decode(&join_data.verifying_key_b64, "verifying_key_b64")?;
        let identity_public = decode(&join_data.identity_public_b64, "identity_public_b64")?;
        let signed_prekey_public = decode(
            &join_data.signed_prekey_public_b64,
            "signed_prekey_public_b64",
        )?;
        let signed_prekey_signature = decode(
            &join_data.signed_prekey_signature_b64,
            "signed_prekey_signature_b64",
        )?;

        let hostname = self.context.config.instance_domain.clone();
        let crypto_suite = if req.crypto_suite.is_empty() {
            "Curve25519+Ed25519".to_string()
        } else {
            req.crypto_suite
        };

        verify_spk_signature(
            &verifying_key,
            &signed_prekey_public,
            &signed_prekey_signature,
        )?;

        let device_data = construct_db::CreateDeviceData {
            device_id: req.pending_device_id.clone(),
            server_hostname: hostname,
            verifying_key,
            identity_public,
            signed_prekey_public,
            signed_prekey_signature,
            crypto_suites: format!("[\"{crypto_suite}\"]"),
            supports_pq_ratchet: false,
        };

        construct_db::create_device(self.context.db_pool.as_ref(), device_data, Some(user_id))
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("IDENTITY_KEY_CONFLICT") {
                    Status::already_exists("Identity key already registered by another device")
                } else {
                    Status::internal(format!("Failed to create device: {msg}"))
                }
            })?;

        let (access_token, _, exp_timestamp) = self
            .context
            .auth_manager
            .create_token_for_device(&user_id, Some(&req.pending_device_id))
            .map_err(|e| Status::internal(format!("Failed to create access token: {e}")))?;

        let (refresh_token, refresh_jti, _) = self
            .context
            .auth_manager
            .create_refresh_token_for_device(&user_id, Some(&req.pending_device_id))
            .map_err(|e| Status::internal(format!("Failed to create refresh token: {e}")))?;

        let refresh_ttl =
            self.context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;
        {
            let mut queue = self.context.queue.lock().await;
            queue
                .store_refresh_token(&refresh_jti, &user_id.to_string(), refresh_ttl)
                .await
                .map_err(|e| Status::internal(format!("Failed to store refresh token: {e}")))?;
        }

        let approved_value = format!(
            "{}:{}:{}:{}",
            access_token, refresh_token, user_id, exp_timestamp
        );
        {
            let mut queue = self.context.queue.lock().await;
            queue
                .store_join_approved(&req.pending_device_id, &approved_value)
                .await
                .map_err(|e| Status::internal(format!("Failed to store approval: {e}")))?;
        }

        tracing::info!(
            approver_user_id = %user_id,
            new_device_id = %req.pending_device_id,
            "Join request approved — device linked"
        );

        Ok(Response::new(proto::ApproveJoinRequestResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: user_id.to_string(),
                access_token,
                refresh_token,
                expires_at: exp_timestamp,
                veil_bridge_cert: self.veil_bridge_cert.clone(),
            }),
        }))
    }

    async fn issue_tokens(
        &self,
        request: Request<proto::IssueTokensRequest>,
    ) -> Result<Response<proto::IssueTokensResponse>, Status> {
        use curve25519_dalek::{
            RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::IsIdentity,
        };

        let k_bytes = self
            .token_issuer_key
            .ok_or_else(|| Status::unavailable("privacy pass: token issuance not configured"))?;
        let k = Scalar::from_bytes_mod_order(k_bytes);

        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {}", e)))?;
        let user_id = claims.sub.clone();

        let blinded_points = &request.get_ref().blinded_points;
        if blinded_points.is_empty() || blinded_points.len() > 20 {
            return Err(Status::invalid_argument(
                "blinded_points: must have 1–20 entries",
            ));
        }

        let count = self
            .context
            .queue
            .lock()
            .await
            .increment_token_issuance_count(&user_id, blinded_points.len() as u64)
            .await
            .map_err(|e| Status::resource_exhausted(format!("rate limit error: {}", e)))?;
        if count > 20 {
            return Err(Status::resource_exhausted(
                "token issuance rate limit exceeded (20/hr)",
            ));
        }

        let mut evaluated_points: Vec<Vec<u8>> = Vec::with_capacity(blinded_points.len());
        for raw in blinded_points {
            if raw.len() != 32 {
                return Err(Status::invalid_argument(
                    "each blinded point must be exactly 32 bytes",
                ));
            }
            let compressed = CompressedRistretto::from_slice(raw)
                .map_err(|_| Status::invalid_argument("blinded point: wrong length"))?;
            let point = compressed
                .decompress()
                .ok_or_else(|| Status::invalid_argument("blinded point: not on ristretto255"))?;
            if point.is_identity() {
                return Err(Status::invalid_argument(
                    "blinded point: identity point not allowed",
                ));
            }
            let z: RistrettoPoint = k * point;
            evaluated_points.push(z.compress().to_bytes().to_vec());
        }

        let pubkey_point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * k;
        let pubkey_bytes = pubkey_point.compress().to_bytes().to_vec();

        Ok(Response::new(proto::IssueTokensResponse {
            evaluated_points,
            server_pubkey: pubkey_bytes,
        }))
    }
}

// ============================================================================
// DeviceService implementation
// ============================================================================

#[tonic::async_trait]
impl proto::device_service_server::DeviceService for IdentityGrpcService {
    type ListDevicesStream = std::pin::Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<
                    Item = Result<proto::ListDevicesResponse, Status>,
                > + Send
                + 'static,
        >,
    >;

    async fn list_devices(
        &self,
        request: Request<proto::ListDevicesRequest>,
    ) -> Result<Response<Self::ListDevicesStream>, Status> {
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let devices = construct_db::get_devices_by_user_id(self.context.db_pool.as_ref(), &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let items: Vec<Result<proto::ListDevicesResponse, Status>> = devices
            .into_iter()
            .map(|d| {
                Ok(proto::ListDevicesResponse {
                    device: Some(proto::DeviceInfo {
                        device: Some(construct_server_shared::shared::proto::core::v1::DeviceId {
                            user: None,
                            device_id: d.device_id.clone(),
                            platform: 0,
                            device_name: None,
                            registered_at: d.registered_at.timestamp(),
                            last_seen: 0,
                            capabilities: 0,
                        }),
                        device_name: String::new(),
                        platform: 0,
                        last_seen: 0,
                        created_at: d.registered_at.timestamp(),
                        push_provider: None,
                        is_current: false,
                        capabilities: 0,
                    }),
                })
            })
            .collect();

        Ok(Response::new(Box::pin(tokio_stream::iter(items))))
    }

    async fn revoke_device(
        &self,
        request: Request<proto::RevokeDeviceRequest>,
    ) -> Result<Response<proto::RevokeDeviceResponse>, Status> {
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let req = request.into_inner();
        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let device = construct_db::get_device_by_id(self.context.db_pool.as_ref(), &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("device not found"))?;

        if device.user_id != Some(user_id) {
            return Err(Status::permission_denied(
                "device does not belong to this user",
            ));
        }

        let deactivated =
            construct_db::deactivate_device(self.context.db_pool.as_ref(), &req.device_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        if deactivated {
            let mut queue = self.context.queue.lock().await;
            let _ = queue.revoke_all_sessions(&req.device_id).await;
        }

        tracing::info!(
            caller_user_id = %user_id,
            revoked_device_id = %req.device_id,
            "Device revoked"
        );

        Ok(Response::new(proto::RevokeDeviceResponse {
            success: deactivated,
            revoked_device: None,
        }))
    }

    async fn update_push_token(
        &self,
        request: Request<proto::UpdatePushTokenRequest>,
    ) -> Result<Response<proto::UpdatePushTokenResponse>, Status> {
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let req = request.into_inner();
        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if req.push_token.is_empty() {
            return Err(Status::invalid_argument("push_token is required"));
        }

        let provider = match req.provider {
            1 => "apns",
            2 => "fcm",
            _ => "apns",
        };
        let environment = match req.environment {
            2 => "production",
            _ => "sandbox",
        };

        use construct_server_shared::apns::DeviceTokenEncryption;
        let token_hash = DeviceTokenEncryption::hash_token(&req.push_token);
        let token_encryption =
            DeviceTokenEncryption::from_hex(&self.context.config.apns.device_token_encryption_key)
                .map_err(|e| Status::internal(format!("Token encryption unavailable: {e}")))?;
        let token_encrypted = token_encryption
            .encrypt(&req.push_token)
            .map_err(|e| Status::internal(format!("Failed to encrypt token: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO device_tokens
                (user_id, device_token_hash, device_token_encrypted, device_name_encrypted,
                 notification_filter, enabled, device_id, push_provider, push_environment)
            VALUES ($1, $2, $3, NULL, 'silent', TRUE, $4, $5, $6)
            ON CONFLICT (user_id, device_id) WHERE device_id IS NOT NULL
            DO UPDATE SET
                device_token_hash      = EXCLUDED.device_token_hash,
                device_token_encrypted = EXCLUDED.device_token_encrypted,
                push_provider          = EXCLUDED.push_provider,
                push_environment       = EXCLUDED.push_environment,
                enabled                = TRUE
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(token_encrypted)
        .bind(req.device_id.clone())
        .bind(provider)
        .bind(environment)
        .execute(self.context.db_pool.as_ref())
        .await
        .map_err(|e| Status::internal(format!("DB error: {e}")))?;

        tracing::info!(
            device_id = %req.device_id,
            provider  = %provider,
            "Push token updated"
        );

        Ok(Response::new(proto::UpdatePushTokenResponse {
            success: true,
        }))
    }

    async fn unregister_push_token(
        &self,
        request: Request<proto::UnregisterPushTokenRequest>,
    ) -> Result<Response<proto::UnregisterPushTokenResponse>, Status> {
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let req = request.into_inner();
        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let result =
            sqlx::query(r#"DELETE FROM device_tokens WHERE user_id = $1 AND device_id = $2"#)
                .bind(user_id)
                .bind(&req.device_id)
                .execute(self.context.db_pool.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {e}")))?;

        Ok(Response::new(proto::UnregisterPushTokenResponse {
            success: result.rows_affected() > 0,
        }))
    }

    async fn verify_device(
        &self,
        _request: Request<proto::VerifyDeviceRequest>,
    ) -> Result<Response<proto::VerifyDeviceResponse>, Status> {
        Err(Status::unimplemented("VerifyDevice not implemented"))
    }

    async fn get_device_info(
        &self,
        _request: Request<proto::GetDeviceInfoRequest>,
    ) -> Result<Response<proto::GetDeviceInfoResponse>, Status> {
        Err(Status::unimplemented("GetDeviceInfo not implemented"))
    }

    async fn initiate_device_link(
        &self,
        request: Request<proto::InitiateDeviceLinkRequest>,
    ) -> Result<Response<proto::InitiateDeviceLinkResponse>, Status> {
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;

        use base64::Engine;
        let raw: [u8; 32] = rand::random();
        let link_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let expires_at = chrono::Utc::now().timestamp() + 15 * 60;

        let mut queue = self.context.queue.lock().await;
        queue
            .store_device_link_token(&link_token, &claims.sub)
            .await
            .map_err(|e| Status::internal(format!("Failed to store link token: {e}")))?;

        tracing::info!(user_id = %claims.sub, "Device link initiated (15 min TTL)");

        Ok(Response::new(proto::InitiateDeviceLinkResponse {
            link_token,
            expires_at,
        }))
    }
}

// ============================================================================
// DeviceLinkService implementation
// ============================================================================

#[tonic::async_trait]
impl proto::device_link_service_server::DeviceLinkService for IdentityGrpcService {
    async fn confirm_device_link(
        &self,
        request: Request<proto::ConfirmDeviceLinkRequest>,
    ) -> Result<Response<proto::ConfirmDeviceLinkResponse>, Status> {
        let req = request.into_inner();

        if req.link_token.is_empty() {
            return Err(Status::invalid_argument("link_token is required"));
        }
        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        let public_keys = req
            .public_keys
            .ok_or_else(|| Status::invalid_argument("public_keys is required"))?;

        let user_id_str = {
            let mut queue = self.context.queue.lock().await;
            queue
                .consume_device_link_token(&req.link_token)
                .await
                .map_err(|e| Status::internal(format!("Redis error: {e}")))?
        }
        .ok_or_else(|| Status::unauthenticated("invalid or expired link token"))?;

        let user_id = uuid::Uuid::parse_str(&user_id_str)
            .map_err(|_| Status::internal("invalid user id in link token"))?;

        if construct_db::device_exists(self.context.db_pool.as_ref(), &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::already_exists("device_id already registered"));
        }

        let verifying_key = public_keys.verifying_key;
        let signed_prekey_public = public_keys.signed_prekey_public;
        let signed_prekey_signature = public_keys.signed_prekey_signature;

        verify_spk_signature(
            &verifying_key,
            &signed_prekey_public,
            &signed_prekey_signature,
        )?;

        let device_data = construct_db::CreateDeviceData {
            device_id: req.device_id.clone(),
            server_hostname: self.context.config.instance_domain.clone(),
            verifying_key,
            identity_public: public_keys.identity_public,
            signed_prekey_public,
            signed_prekey_signature,
            crypto_suites: format!("[\"{}\"]", public_keys.crypto_suite),
            supports_pq_ratchet: false,
        };

        construct_db::create_device(self.context.db_pool.as_ref(), device_data, Some(user_id))
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("IDENTITY_KEY_CONFLICT") {
                    Status::already_exists("Identity key already registered by another device")
                } else {
                    Status::internal(format!("Failed to create device: {msg}"))
                }
            })?;

        let (access_token, _, exp_timestamp) = self
            .context
            .auth_manager
            .create_token_for_device(&user_id, Some(&req.device_id))
            .map_err(|e| Status::internal(format!("Failed to create access token: {e}")))?;

        let (refresh_token, refresh_jti, _) = self
            .context
            .auth_manager
            .create_refresh_token_for_device(&user_id, Some(&req.device_id))
            .map_err(|e| Status::internal(format!("Failed to create refresh token: {e}")))?;

        let refresh_ttl =
            self.context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;
        {
            let mut queue = self.context.queue.lock().await;
            queue
                .store_refresh_token(&refresh_jti, &user_id_str, refresh_ttl)
                .await
                .map_err(|e| Status::internal(format!("Failed to store refresh token: {e}")))?;
        }

        tracing::info!(user_id = %user_id_str, device_id = %req.device_id, "Device linked");

        Ok(Response::new(proto::ConfirmDeviceLinkResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: user_id_str,
                access_token,
                refresh_token,
                expires_at: exp_timestamp,
                veil_bridge_cert: self.veil_bridge_cert.clone(),
            }),
        }))
    }

    async fn submit_join_request(
        &self,
        request: Request<proto::JoinRequestPayload>,
    ) -> Result<Response<proto::JoinRequestAck>, Status> {
        let req = request.into_inner();

        if req.pending_device_id.is_empty() {
            return Err(Status::invalid_argument("pending_device_id is required"));
        }
        if req.identity_public_b64.is_empty() {
            return Err(Status::invalid_argument("identity_public_b64 is required"));
        }
        if req.verifying_key_b64.is_empty() {
            return Err(Status::invalid_argument("verifying_key_b64 is required"));
        }
        if req.signed_prekey_public_b64.is_empty() {
            return Err(Status::invalid_argument(
                "signed_prekey_public_b64 is required",
            ));
        }
        if req.signed_prekey_signature_b64.is_empty() {
            return Err(Status::invalid_argument(
                "signed_prekey_signature_b64 is required",
            ));
        }

        if construct_db::device_exists(self.context.db_pool.as_ref(), &req.pending_device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::already_exists("device_id already registered"));
        }

        let pending_device_id = req.pending_device_id.clone();
        let data = JoinRequestData {
            pending_device_id: req.pending_device_id,
            identity_public_b64: req.identity_public_b64,
            verifying_key_b64: req.verifying_key_b64,
            signed_prekey_public_b64: req.signed_prekey_public_b64,
            signed_prekey_signature_b64: req.signed_prekey_signature_b64,
            device_name: req.device_name,
            platform: req.platform,
        };

        let json_payload = serde_json::to_string(&data)
            .map_err(|e| Status::internal(format!("serialize: {e}")))?;

        {
            let mut queue = self.context.queue.lock().await;
            queue
                .store_join_request(&pending_device_id, &json_payload)
                .await
                .map_err(|e| Status::internal(format!("Failed to store join request: {e}")))?;
        }

        tracing::info!(pending_device_id = %pending_device_id, "Join request stored (10 min TTL)");

        Ok(Response::new(proto::JoinRequestAck { pending_device_id }))
    }

    async fn check_join_request_status(
        &self,
        request: Request<proto::CheckJoinRequestStatusRequest>,
    ) -> Result<Response<proto::CheckJoinRequestStatusResponse>, Status> {
        let req = request.into_inner();
        if req.pending_device_id.is_empty() {
            return Err(Status::invalid_argument("pending_device_id is required"));
        }

        let approved_value = {
            let mut queue = self.context.queue.lock().await;
            queue
                .get_join_approved(&req.pending_device_id)
                .await
                .map_err(|e| Status::internal(format!("Redis error: {e}")))?
        };

        if let Some(value) = approved_value {
            let parts: Vec<&str> = value.splitn(4, ':').collect();
            if parts.len() == 4 {
                let exp_timestamp: i64 = parts[3]
                    .parse()
                    .map_err(|_| Status::internal("invalid exp in approved data"))?;
                return Ok(Response::new(proto::CheckJoinRequestStatusResponse {
                    status: proto::check_join_request_status_response::Status::Approved as i32,
                    tokens: Some(proto::AuthTokensResponse {
                        user_id: parts[2].to_string(),
                        access_token: parts[0].to_string(),
                        refresh_token: parts[1].to_string(),
                        expires_at: exp_timestamp,
                        veil_bridge_cert: self.veil_bridge_cert.clone(),
                    }),
                }));
            }
        }

        let join_request_exists = {
            let mut queue = self.context.queue.lock().await;
            queue
                .get_join_request(&req.pending_device_id)
                .await
                .map_err(|e| Status::internal(format!("Redis error: {e}")))?
                .is_some()
        };

        let status = if join_request_exists {
            proto::check_join_request_status_response::Status::Pending
        } else {
            proto::check_join_request_status_response::Status::Expired
        };

        Ok(Response::new(proto::CheckJoinRequestStatusResponse {
            status: status as i32,
            tokens: None,
        }))
    }
}

// ============================================================================
// UserService implementation
// ============================================================================

#[tonic::async_trait]
impl UserService for IdentityGrpcService {
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
                username: None,
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
            let hash = construct_crypto::hash_username(secret, username);
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
            construct_crypto::hash_username(secret, u)
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
                username: None,
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
            "update_profile_picture not implemented",
        ))
    }

    async fn get_user_capabilities(
        &self,
        request: Request<proto::GetUserCapabilitiesRequest>,
    ) -> Result<Response<proto::GetUserCapabilitiesResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let caps = construct_db::get_user_capabilities(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        let crypto_suites: Vec<String> = caps
            .crypto_suites
            .iter()
            .map(|s| format!("{:?}", s))
            .collect();
        let supports_pq = crypto_suites
            .iter()
            .any(|s| s.contains("Hybrid") || s.contains("Kyber"));

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
        let blocker_id = uuid::Uuid::parse_str(&req.blocker_user_id)
            .map_err(|_| Status::invalid_argument("invalid blocker_user_id"))?;
        let blocked_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        if blocker_id == blocked_id {
            return Err(Status::invalid_argument("cannot block self"));
        }

        if construct_server_shared::db::get_user_by_id(&self.context.db_pool, &blocked_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .is_none()
        {
            return Err(Status::not_found("user not found"));
        }

        let blocked_at = construct_server_shared::db::block_user(
            &self.context.db_pool,
            &blocker_id,
            &blocked_id,
            req.reason.as_deref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        {
            let blocker_str = blocker_id.to_string();
            let blocked_str = blocked_id.to_string();
            let queue = self.context.queue.clone();
            tokio::spawn(async move {
                let mut q = queue.lock().await;
                if let Err(e) = q
                    .purge_stream_messages_from_sender(&blocker_str, &blocked_str)
                    .await
                {
                    tracing::warn!(error = %e, "Stream purge on block failed");
                }
            });
        }

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
        let blocker_id = uuid::Uuid::parse_str(&req.blocker_user_id)
            .map_err(|_| Status::invalid_argument("invalid blocker_user_id"))?;
        let blocked_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let success = construct_server_shared::db::unblock_user(
            &self.context.db_pool,
            &blocker_id,
            &blocked_id,
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
                username: String::new(),
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
        let user_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        if req.confirmation.trim().to_uppercase() != "DELETE" {
            return Err(Status::invalid_argument(
                "confirmation must be 'DELETE' to proceed with account deletion",
            ));
        }

        construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        {
            let mut queue = self.context.queue.lock().await;
            if let Err(e) = queue.revoke_all_user_tokens(&user_id.to_string()).await {
                tracing::warn!(error = %e, "Failed to revoke Redis tokens during account deletion");
            }
        }

        construct_server_shared::db::delete_user_account(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete account: {}", e)))?;

        tracing::info!(
            target: "audit",
            event_type = "ACCOUNT_DELETION",
            user_id = %user_id,
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
        let user_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;

        let user = construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

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

        let export_data = json!({
            "export_version": "1.0",
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "data_notice": "Construct is a privacy-first messenger. Message content is never stored on the server.",
            "profile": { "user_id": user.id.to_string(), "username": null, "account_created": null },
            "devices": device_list,
        });

        tracing::info!(target: "audit", event_type = "DATA_EXPORT", user_id = %user_id, "GDPR: User data exported");

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

        let secret = &self.context.config.security.username_hmac_secret;
        let hash = construct_crypto::hash_username(secret, &normalized);
        match construct_server_shared::db::get_user_by_username_hash(&self.context.db_pool, &hash)
            .await
        {
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
        let user_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let discoverable = request.into_inner().discoverable;

        if discoverable {
            let user = construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::not_found("user not found"))?;

            if user.username_hash.is_none() {
                return Err(Status::failed_precondition(
                    "A username must be set before enabling discoverability",
                ));
            }
        }

        construct_server_shared::db::set_user_searchable(
            &self.context.db_pool,
            &user_id,
            discoverable,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::SetDiscoverableResponse {
            discoverable,
        }))
    }

    async fn find_user(
        &self,
        request: Request<proto::FindUserRequest>,
    ) -> Result<Response<proto::FindUserResponse>, Status> {
        let caller_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();
        if req.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

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
            return Err(Status::not_found("user not found"));
        }

        let secret = &self.context.config.security.username_hmac_secret;
        let hash = construct_crypto::hash_username(secret, &normalized);

        match construct_server_shared::db::find_discoverable_user_by_username_hash(
            &self.context.db_pool,
            &hash,
        )
        .await
        {
            Ok(Some(found_id)) => Ok(Response::new(proto::FindUserResponse {
                user_id: found_id.to_string(),
            })),
            Ok(None) => Err(Status::not_found("user not found")),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn send_contact_request(
        &self,
        request: Request<proto::SendContactRequestRequest>,
    ) -> Result<Response<proto::SendContactRequestResponse>, Status> {
        let caller_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();
        let to_user_id = uuid::Uuid::parse_str(&req.to_user_id)
            .map_err(|_| Status::invalid_argument("Invalid to_user_id"))?;

        if caller_id == to_user_id {
            return Err(Status::invalid_argument("Cannot send request to yourself"));
        }

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

        let searchable = construct_db::is_user_searchable(&self.context.db_pool, &to_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if !searchable {
            return Err(Status::not_found("user not found"));
        }

        let is_blocked = construct_server_shared::db::is_blocked_by(
            &self.context.db_pool,
            &to_user_id,
            &caller_id,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        if is_blocked {
            return Err(Status::not_found("user not found"));
        }

        let sec = &self.context.config.security;

        if let Some(existing_id) = construct_db::get_pending_contact_request_id(
            &self.context.db_pool,
            caller_id,
            to_user_id,
            &sec.contact_hmac_secret,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        {
            return Ok(Response::new(proto::SendContactRequestResponse {
                request_id: existing_id.to_string(),
                status: proto::ContactRequestStatus::Pending as i32,
            }));
        }

        let from_identity_enc = match req.from_identity {
            Some(identity) => {
                let normalized_username = identity.username.trim().to_lowercase();
                let snapshot_username = if !normalized_username.is_empty() {
                    let caller = construct_db::get_user_by_id(&self.context.db_pool, &caller_id)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?
                        .ok_or_else(|| Status::internal("Caller user not found"))?;

                    if let Some(ref stored_hash) = caller.username_hash {
                        let supplied_hash = construct_crypto::hash_username(
                            &sec.username_hmac_secret,
                            &normalized_username,
                        );
                        if supplied_hash != *stored_hash {
                            return Err(Status::invalid_argument(
                                "from_identity.username does not match caller's username",
                            ));
                        }
                        normalized_username
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                let display_name = {
                    let trimmed = identity.display_name.trim().to_string();
                    if trimmed.len() > 128 {
                        return Err(Status::invalid_argument(
                            "from_identity.display_name too long (max 128 bytes)",
                        ));
                    }
                    trimmed
                };

                let snapshot = construct_db::ContactIdentitySnapshot {
                    username: snapshot_username,
                    display_name,
                };
                let json_bytes =
                    serde_json::to_vec(&snapshot).map_err(|e| Status::internal(e.to_string()))?;
                let enc =
                    construct_crypto::envelope_encrypt(&sec.request_envelope_key, &json_bytes)
                        .map_err(|e| Status::internal(e.to_string()))?;
                Some(enc)
            }
            None => None,
        };

        let request_id = construct_db::create_contact_request(
            &self.context.db_pool,
            caller_id,
            to_user_id,
            &sec.contact_hmac_secret,
            &sec.request_envelope_key,
            from_identity_enc.as_deref(),
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
        let caller_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let sec = &self.context.config.security;

        let incoming_raw = construct_db::get_pending_contact_requests(
            &self.context.db_pool,
            caller_id,
            &sec.contact_hmac_secret,
            &sec.request_envelope_key,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let incoming = incoming_raw
            .into_iter()
            .map(|cr| proto::IncomingContactRequest {
                request_id: cr.id.to_string(),
                from_user_id: cr.from_user_id.to_string(),
                from_display_name: cr.from_display_name,
                from_username: cr.from_username,
                created_at: cr.created_at.timestamp(),
            })
            .collect();

        let sent_raw = construct_db::get_sent_contact_requests(
            &self.context.db_pool,
            caller_id,
            &sec.contact_hmac_secret,
        )
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
        let caller_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
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

        let from_user_id = if action == proto::ContactRequestAction::Accept {
            Some(
                construct_db::get_contact_request_sender(
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

        construct_db::respond_to_contact_request(
            &self.context.db_pool,
            request_id,
            caller_id,
            db_status,
            &sec.contact_hmac_secret,
        )
        .await
        .map_err(|e| Status::not_found(e.to_string()))?;

        use construct_crypto::hmac_sha256;

        if action == proto::ContactRequestAction::Accept {
            if let Some(sender_id) = from_user_id {
                let caller_hmac = hmac_sha256(&sec.contact_hmac_secret, caller_id.as_bytes());
                let sender_hmac = hmac_sha256(&sec.contact_hmac_secret, sender_id.as_bytes());
                construct_server_shared::db::add_contact_link(
                    &self.context.db_pool,
                    &caller_hmac,
                    &sender_hmac,
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
                construct_server_shared::db::add_contact_link(
                    &self.context.db_pool,
                    &sender_hmac,
                    &caller_hmac,
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

                if let Some(notification_client) = &self.context.notification_client
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
                        }
                        Err(e) => {
                            notification_client.record_failure();
                            tracing::warn!(error = %e, to_user = %sender_id, "Failed to send contact_request_accepted push");
                        }
                    }
                }
            }
        } else {
            let sender_id = construct_db::get_contact_request_sender(
                &self.context.db_pool,
                request_id,
                caller_id,
                &sec.contact_hmac_secret,
                &sec.request_envelope_key,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

            construct_server_shared::db::block_user(
                &self.context.db_pool,
                &caller_id,
                &sender_id,
                None,
            )
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
                proto::ContactRequestAction::Unspecified => unreachable!(),
            } as i32,
        }))
    }

    async fn set_group_invite_policy(
        &self,
        request: Request<proto::SetGroupInvitePolicyRequest>,
    ) -> Result<Response<proto::SetGroupInvitePolicyResponse>, Status> {
        let user_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let allow = request.into_inner().allow_contact_invites;

        construct_server_shared::db::set_user_group_invite_policy(
            &self.context.db_pool,
            &user_id,
            allow,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::SetGroupInvitePolicyResponse {
            allow_contact_invites: allow,
        }))
    }
}

// ============================================================================
// InviteService implementation
// ============================================================================

#[tonic::async_trait]
impl InviteService for IdentityGrpcService {
    async fn generate_invite(
        &self,
        request: Request<proto::GenerateInviteRequest>,
    ) -> Result<Response<proto::GenerateInviteResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id_from_metadata(&self.context.auth_manager, metadata)?;
        let device_id = metadata
            .get("x-device-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let req = request.into_inner();

        let output = invite_core::generate_invite(
            &self.context,
            invite_core::GenerateInviteInput {
                user_id,
                device_id,
                ttl_seconds: req.ttl_seconds,
            },
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to generate invite: {}", e)))?;

        Ok(Response::new(proto::GenerateInviteResponse {
            jti: output.jti,
            server: output.server,
            expires_at: output.expires_at,
            user_id: output.user_id,
            device_id: output.device_id,
            ttl_seconds: output.ttl_seconds,
        }))
    }

    async fn accept_invite(
        &self,
        request: Request<proto::AcceptInviteRequest>,
    ) -> Result<Response<proto::AcceptInviteResponse>, Status> {
        let metadata = request.metadata();
        let accepter_user_id = extract_user_id_from_metadata(&self.context.auth_manager, metadata)?;
        let req = request.into_inner();

        let invite_token = req
            .invite
            .ok_or_else(|| Status::invalid_argument("Missing invite token"))?;

        let invite = crypto_agility::InviteToken {
            v: invite_token.v as u32,
            jti: uuid::Uuid::parse_str(&invite_token.jti)
                .map_err(|_| Status::invalid_argument("Invalid jti UUID"))?,
            uuid: uuid::Uuid::parse_str(&invite_token.uuid)
                .map_err(|_| Status::invalid_argument("Invalid user UUID"))?,
            device_id: invite_token.device_id,
            server: invite_token.server,
            eph_key: invite_token.eph_pub,
            ts: invite_token.ts,
            sig: invite_token.sig,
            username: invite_token.un,
        };

        let output = invite_core::accept_invite(
            &self.context,
            invite_core::AcceptInviteInput {
                accepter_user_id,
                invite,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to accept invite");
            Status::invalid_argument(format!("Failed to accept invite: {}", e))
        })?;

        Ok(Response::new(proto::AcceptInviteResponse {
            user_id: output.user_id,
            device_id: output.device_id,
            server: output.server,
            message: output.message,
        }))
    }

    async fn revoke_invite(
        &self,
        request: Request<proto::RevokeInviteRequest>,
    ) -> Result<Response<proto::RevokeInviteResponse>, Status> {
        let user_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let output = invite_core::revoke_invite(
            &self.context,
            invite_core::RevokeInviteInput {
                user_id,
                jti: req.jti,
            },
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to revoke invite: {}", e)))?;

        Ok(Response::new(proto::RevokeInviteResponse {
            success: output.success,
            message: output.message,
        }))
    }

    async fn list_invites(
        &self,
        request: Request<proto::ListInvitesRequest>,
    ) -> Result<Response<proto::ListInvitesResponse>, Status> {
        let user_id =
            extract_user_id_from_metadata(&self.context.auth_manager, request.metadata())?;
        let req = request.into_inner();

        let output = invite_core::list_invites(
            &self.context,
            invite_core::ListInvitesInput {
                user_id,
                limit: req.limit,
                include_expired: req.include_expired.unwrap_or(false),
            },
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to list invites: {}", e)))?;

        let invites = output
            .invites
            .into_iter()
            .map(|inv| proto::InviteInfo {
                jti: inv.jti,
                user_id: inv.user_id,
                device_id: inv.device_id,
                created_at: inv.created_at,
                expires_at: inv.expires_at,
                used: inv.used,
                used_by: inv.used_by,
                used_at: inv.used_at,
            })
            .collect();

        Ok(Response::new(proto::ListInvitesResponse { invites }))
    }
}

// ============================================================================
// HTTP handlers
// ============================================================================

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

async fn get_jwks() -> impl IntoResponse {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::traits::PublicKeyParts as _;

    let raw = match env::var("JWT_PUBLIC_KEY") {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "JWT_PUBLIC_KEY not configured"})),
            );
        }
    };

    let pem = raw.replace("\\n", "\n");
    let public_key = rsa::RsaPublicKey::from_public_key_pem(&pem)
        .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(&pem));

    match public_key {
        Ok(key) => {
            let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
            let jwks = json!({
                "keys": [{
                    "kty": "RSA", "use": "sig", "alg": "RS256",
                    "kid": "construct-auth-key", "n": n, "e": e
                }]
            });
            (StatusCode::OK, Json(jwks))
        }
        Err(e) => {
            tracing::error!("Failed to parse JWT_PUBLIC_KEY for JWKS: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to parse JWT public key"})),
            )
        }
    }
}

async fn get_public_key() -> impl IntoResponse {
    match env::var("JWT_PUBLIC_KEY") {
        Ok(key) => (StatusCode::OK, key),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "JWT public key not configured".to_string(),
        ),
    }
}

async fn well_known_construct_server(
    State(context): State<Arc<IdentityServiceContext>>,
) -> impl IntoResponse {
    use axum::http::header;

    let app_context = Arc::new(context.to_app_context());

    let public_key = app_context
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    let token_encryption_key = context
        .token_enc_pub
        .as_ref()
        .map(|bytes| b64::STANDARD.encode(bytes));

    let paseto_public_key = app_context
        .config
        .paseto_public_key
        .as_ref()
        .and_then(|pem| {
            let pem = pem.replace("\\n", "\n");
            ed25519_compact::PublicKey::from_pem(pem.as_str())
                .ok()
                .map(|pk| b64::URL_SAFE_NO_PAD.encode(pk.as_ref()))
        });

    let domain = &app_context.config.instance_domain;
    let tls_enabled = public_key.is_some();

    let discovery_info = json!({
        "version": "1.0",
        "protocol": "grpc",
        "server": {
            "domain": domain,
            "version": env!("CARGO_PKG_VERSION"),
            "public_key": public_key,
            "token_encryption_key": token_encryption_key,
            "paseto_public_key": paseto_public_key,
        },
        "grpc_endpoint": format!("{}:443", domain),
        "services": [
            "auth.AuthService", "user.UserService", "messaging.MessagingService",
            "notification.NotificationService", "invite.InviteService", "media.MediaService"
        ],
        "federation": {
            "enabled": app_context.config.federation_enabled,
            "protocol_version": "1.0",
            "public_key": public_key,
            "s2s_endpoint": format!("{}:443", domain),
            "tls": tls_enabled
        },
        "capabilities": {
            "max_message_size_bytes": 100_000,
            "max_file_size_bytes": 100_000_000,
            "supports_streaming": true,
            "supports_grpc_web": true,
            "supports_pq_crypto": false
        },
        "limits": {
            "max_message_size_bytes": 100_000,
            "max_media_size_bytes": 100_000_000,
            "rate_limit_messages_per_hour": app_context.config.security.max_messages_per_hour,
            "rate_limit_pow_per_hour": 10
        }
    });

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(discovery_info),
    )
}

// ============================================================================
// SPK signature verification (shared by multiple gRPC methods)
// ============================================================================

fn verify_spk_signature(
    verifying_key: &[u8],
    signed_prekey_public: &[u8],
    signed_prekey_signature: &[u8],
) -> Result<(), Status> {
    let vk_bytes: [u8; 32] = verifying_key
        .try_into()
        .map_err(|_| Status::invalid_argument("verifying_key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|_| Status::invalid_argument("verifying_key is not a valid Ed25519 key"))?;
    let sig_bytes: [u8; 64] = signed_prekey_signature
        .try_into()
        .map_err(|_| Status::invalid_argument("signed_prekey_signature must be 64 bytes"))?;
    let sig = Ed25519Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(18 + signed_prekey_public.len());
    msg.extend_from_slice(b"KonstruktX3DH-v1");
    msg.extend_from_slice(&[0x00, 0x01]);
    msg.extend_from_slice(signed_prekey_public);
    vk.verify(&msg, &sig)
        .map_err(|_| Status::invalid_argument("signed_prekey_signature verification failed"))
}

// ============================================================================
// main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let config = Arc::new(config);

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== Identity Service Starting (auth + user + invite) ===");
    info!("Port: {}", config.port);

    info!("Connecting to database...");
    let db_pool = Arc::new(
        DbPool::connect(&config.database_url)
            .await
            .context("Failed to connect to database")?,
    );
    info!("Connected to database");

    info!("Applying database migrations...");
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await
        .context("Failed to apply database migrations")?;
    info!("Database migrations applied");

    info!("Connecting to Redis...");
    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .context("Failed to create message queue")?,
    ));
    info!("Connected to Redis");

    let auth_manager = Arc::new(
        construct_server_shared::auth::AuthManager::new(&config)
            .context("Failed to initialize auth manager")?,
    );

    let server_signer = config
        .federation
        .signing_key_seed
        .as_ref()
        .and_then(|seed| {
            construct_server_shared::federation::ServerSigner::from_seed_base64(
                seed,
                config.federation.instance_domain.clone(),
            )
            .map(Arc::new)
            .map_err(
                |e| tracing::warn!(error = %e, "Failed to init server signer for sealed sender"),
            )
            .ok()
        });

    let token_enc_pub: Option<[u8; 32]> = config
        .federation
        .signing_key_seed
        .as_ref()
        .and_then(|seed_b64| {
            construct_crypto::privacy_pass::derive_token_enc_static_secret(seed_b64)
        })
        .map(|priv_key| {
            let pub_key = X25519PublicKey::from(&priv_key);
            tracing::info!(
                public_key = %b64::STANDARD.encode(pub_key.as_bytes()),
                "Token encryption key initialized"
            );
            *pub_key.as_bytes()
        });

    let notification_url = env::var("NOTIFICATION_SERVICE_URL")
        .unwrap_or_else(|_| "http://messaging:50053".to_string());
    let notification_client =
        match construct_server_shared::clients::notification::NotificationClient::new(
            &notification_url,
        ) {
            Ok(client) => {
                info!(url = %notification_url, "Notification gRPC client initialized");
                Some(client)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create notification gRPC client — contact-accepted push disabled");
                None
            }
        };

    let identity_ctx = Arc::new(IdentityServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
        server_signer,
        token_enc_pub,
        notification_client,
    });

    // VEIL bridge cert
    let veil_bridge_cert: Option<String> = if config.veil_enabled {
        config.veil_server_key.as_ref().and_then(|key_b64| {
            let bytes = b64::STANDARD
                .decode(key_b64)
                .map_err(|e| tracing::warn!(error = %e, "VEIL_SERVER_KEY: invalid base64"))
                .ok()?;
            let server_cfg = construct_veil::ServerConfig::from_bytes(&bytes)
                .map_err(|e| tracing::warn!(error = %e, "VEIL_SERVER_KEY: failed to parse"))
                .ok()?;
            let cert = server_cfg.bridge_cert();
            info!(cert = %cert, "VEIL bridge cert ready");
            Some(cert)
        })
    } else {
        None
    };

    // Privacy Pass token issuer key
    let token_issuer_key: Option<[u8; 32]> = match env::var("TOKEN_ISSUER_KEY") {
        Ok(hex_str) => {
            let bytes = (0..hex_str.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>();
            match bytes {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    info!("Privacy Pass token issuer key loaded — IssueTokens enabled");
                    Some(arr)
                }
                _ => {
                    tracing::warn!("TOKEN_ISSUER_KEY must be 64 hex chars — IssueTokens disabled");
                    None
                }
            }
        }
        Err(_) => {
            info!("TOKEN_ISSUER_KEY not set — IssueTokens disabled");
            None
        }
    };

    // Sender-certificate signing key — same BUNDLE_SIGNING_KEY key-service signs
    // prekey bundles / KT tree heads with, so clients can verify certificates
    // against the bundle_verification_key they already cache from well-known.
    let cert_signing_key: Option<SigningKey> = match env::var("BUNDLE_SIGNING_KEY") {
        Ok(b64_str) => match b64::STANDARD.decode(b64_str.trim()) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes) {
                Ok(seed) => {
                    let sk = SigningKey::from_bytes(&seed);
                    info!(
                        public_key = %b64::STANDARD.encode(sk.verifying_key().to_bytes()),
                        "BUNDLE_SIGNING_KEY loaded — sender certificates signed with bundle key"
                    );
                    Some(sk)
                }
                Err(_) => {
                    tracing::warn!(
                        "BUNDLE_SIGNING_KEY must be 32 bytes — sender certificates will be UNAVAILABLE (sealed sender disabled) until it is fixed"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to decode BUNDLE_SIGNING_KEY — sender certificates will be UNAVAILABLE (sealed sender disabled) until it is fixed");
                None
            }
        },
        Err(_) => {
            tracing::warn!(
                "BUNDLE_SIGNING_KEY not set — sender certificates will be UNAVAILABLE (sealed sender disabled). Set it to the same 32-byte seed key-service uses; the service now refuses to sign with the federation signer rather than issue certs that fail client verification"
            );
            None
        }
    };

    // Cross-service consistency guard (sealed-sender-resilience C′): if the deployment also
    // hands this service the gateway's published bundle key (BUNDLE_SIGNING_PUBLIC_KEY, what
    // clients verify certs/KT against), assert the key we SIGN with equals it. A mismatch is
    // the silent 100%-sealed-drop failure mode — fail fast at boot instead of shipping
    // unverifiable certificates. No-op when the public var isn't provided to this service.
    if let (Some(sk), Ok(published)) = (&cert_signing_key, env::var("BUNDLE_SIGNING_PUBLIC_KEY")) {
        let signing_pub = b64::STANDARD.encode(sk.verifying_key().to_bytes());
        if signing_pub != published.trim() {
            tracing::error!(
                signing_public_key = %signing_pub,
                published_public_key = %published.trim(),
                "BUNDLE_SIGNING_KEY does not match BUNDLE_SIGNING_PUBLIC_KEY — sender certificates would fail client verification against the published bundle key. Refusing to start."
            );
            std::process::exit(1);
        }
        info!("BUNDLE_SIGNING_KEY matches published BUNDLE_SIGNING_PUBLIC_KEY ✓");
    }

    // Build sub-contexts for HTTP handlers that delegate to existing shared handlers
    let auth_svc_ctx = Arc::new(AuthServiceContext {
        db_pool: identity_ctx.db_pool.clone(),
        queue: identity_ctx.queue.clone(),
        auth_manager: identity_ctx.auth_manager.clone(),
        config: identity_ctx.config.clone(),
        server_signer: identity_ctx.server_signer.clone(),
        token_enc_pub: identity_ctx.token_enc_pub,
    });

    let user_svc_ctx = Arc::new(UserServiceContext {
        db_pool: identity_ctx.db_pool.clone(),
        queue: identity_ctx.queue.clone(),
        auth_manager: identity_ctx.auth_manager.clone(),
        config: identity_ctx.config.clone(),
    });

    // Start gRPC server (all 5 services on one port)
    let grpc_bind_address =
        env::var("IDENTITY_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50051".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_address).await?;
    let grpc_keepalive_secs = config.grpc_keepalive_interval_secs;
    let grpc_keepalive_timeout_secs = config.grpc_keepalive_timeout_secs;

    let grpc_ctx = identity_ctx.clone();
    let grpc_veil = veil_bridge_cert.clone();
    tokio::spawn(async move {
        let svc = IdentityGrpcService {
            context: grpc_ctx,
            veil_bridge_cert: grpc_veil,
            token_issuer_key,
            cert_signing_key,
        };
        if let Err(e) =
            construct_server_shared::grpc_server(grpc_keepalive_secs, grpc_keepalive_timeout_secs)
                .add_service(AuthServiceServer::new(svc.clone()))
                .add_service(DeviceServiceServer::new(svc.clone()))
                .add_service(DeviceLinkServiceServer::new(svc.clone()))
                .add_service(UserServiceServer::new(svc.clone()))
                .add_service(InviteServiceServer::new(svc))
                .serve_with_incoming_shutdown(
                    grpc_incoming,
                    construct_server_shared::shutdown_signal(),
                )
                .await
        {
            tracing::error!(error = %e, "Identity gRPC server failed");
        }
    });
    info!(
        "Identity gRPC listening on {} (AuthService + DeviceService + DeviceLinkService + UserService + InviteService)",
        grpc_bind_address
    );

    // HTTP router — sub-routers with their own state, merged into one app
    let auth_http = Router::new()
        .route(
            "/api/v1/auth/challenge",
            get(construct_server_shared::auth_service::handlers::get_pow_challenge),
        )
        .route(
            "/api/v1/auth/register-device",
            post(construct_server_shared::auth_service::handlers::register_device),
        )
        .route(
            "/api/v1/auth/device",
            post(construct_server_shared::auth_service::handlers::authenticate_device),
        )
        .route(
            "/api/v1/auth/refresh",
            post(construct_server_shared::auth_service::handlers::refresh_token),
        )
        .route(
            "/api/v1/auth/logout",
            post(construct_server_shared::auth_service::handlers::logout),
        )
        .with_state(auth_svc_ctx);

    let user_http = Router::new()
        .route(
            "/api/v1/users/me/delete-challenge",
            get(construct_server_shared::user_service::handlers::get_delete_challenge),
        )
        .route(
            "/api/v1/users/me/delete-confirm",
            post(construct_server_shared::user_service::handlers::confirm_delete),
        )
        .with_state(user_svc_ctx);

    let identity_http = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        )
        .route(
            "/.well-known/construct-server",
            get(well_known_construct_server),
        )
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/public-key", get(get_public_key))
        .with_state(identity_ctx);

    let app = Router::new()
        .merge(auth_http)
        .merge(user_http)
        .merge(identity_http)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        );

    info!("Identity Service HTTP listening on {}", config.bind_address);

    let listener = construct_server_shared::mptcp_or_tcp_listener(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start HTTP server")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sender_cert_sign_payload_is_direct_concat_no_separators_be_times() {
        let payload = build_sender_cert_sign_payload(
            "user-123",
            "construct.example",
            &[0xAB; 32],
            "device-1",
            1_000,
            2_000,
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(b"user-123");
        expected.extend_from_slice(b"construct.example");
        expected.extend_from_slice(&[0xAB; 32]);
        expected.extend_from_slice(b"device-1");
        expected.extend_from_slice(&1_000i64.to_be_bytes());
        expected.extend_from_slice(&2_000i64.to_be_bytes());

        assert_eq!(payload, expected);
        // No colon separators anywhere in the payload (old variant 2 used ':').
        assert!(!payload.contains(&b':'));
    }
}
