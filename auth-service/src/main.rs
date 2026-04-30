// ============================================================================
// Auth Service - Phase 2.6.2
// ============================================================================
//
// Authentication and authorization service for microservices architecture.
// Handles:
// - User registration
// - User login
// - JWT token management (access tokens, refresh tokens)
// - Token refresh
// - Logout (token invalidation)
// - Account recovery via seed phrase
//
// Architecture:
// - Stateless (JWT tokens)
// - Horizontally scalable
// - No sticky sessions required
//
// ============================================================================

mod handlers;
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
use construct_server_shared::auth_service::AuthServiceContext;
use construct_server_shared::db::DbPool;
use construct_server_shared::queue::MessageQueue;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    auth_service_server::{AuthService, AuthServiceServer},
    device_link_service_server::DeviceLinkServiceServer,
    device_service_server::DeviceServiceServer,
};

#[derive(Clone)]
struct AuthGrpcService {
    context: Arc<AuthServiceContext>,
    /// Pre-computed obfs4 bridge cert (None when ICE_ENABLED=false or key not set).
    ice_bridge_cert: Option<String>,
    /// OPRF scalar key for Privacy Pass token issuance (None = feature disabled).
    token_issuer_key: Option<[u8; 32]>,
}

/// Data stored in Redis for a join request (Flow B).
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

#[tonic::async_trait]
impl AuthService for AuthGrpcService {
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
                        },
                    pow_solution: construct_server_shared::auth_service::core::PowSolutionInput {
                        challenge: pow_solution.challenge,
                        nonce: pow_solution.nonce,
                        hash: pow_solution.hash,
                    },
                },
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::RegisterDeviceResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: response.user_id,
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
                ice_bridge_cert: self.ice_bridge_cert.clone(),
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
        .map_err(|e| Status::internal(e.to_string()))?;

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

        // Check access token blocklist (populated by logout).
        // Fail-closed: if Redis is unavailable, treat the token as invalidated.
        let invalidated = {
            let mut queue = self.context.queue.lock().await;
            match queue.is_token_invalidated(&claims.jti).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(error = %e, "Redis unavailable during token invalidation check — failing closed");
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
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::AuthenticateDeviceResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: response.user_id,
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
                ice_bridge_cert: self.ice_bridge_cert.clone(),
            }),
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
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::LogoutResponse { success: true }))
    }

    // =========================================================================
    // Account Recovery RPCs
    // =========================================================================

    async fn set_recovery_key(
        &self,
        request: Request<proto::SetRecoveryKeyRequest>,
    ) -> Result<Response<proto::SetRecoveryKeyResponse>, Status> {
        // Extract token before consuming request
        let token = request_token(request.metadata())?;
        let req = request.into_inner();

        // Validate inputs
        if req.recovery_public_key.is_empty() {
            return Err(Status::invalid_argument("recovery_public_key is required"));
        }
        if req.setup_signature.is_empty() {
            return Err(Status::invalid_argument("setup_signature is required"));
        }
        if req.timestamp == 0 {
            return Err(Status::invalid_argument("timestamp is required"));
        }

        // Verify auth token
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let db = self.context.db_pool.as_ref();
        let fingerprint = recovery::set_recovery_key(
            db,
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
        // Must be authenticated
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let db = self.context.db_pool.as_ref();
        let status = recovery::get_recovery_status(db, user_id)
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

        // Validate required fields
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

        // 1. Verify recovery signature and get user_id
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

        // 2. Revoke all existing devices
        let devices_revoked = recovery::revoke_all_devices(db, user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // 3. Revoke all tokens
        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::auth_service::core::logout_user(
            app_context.clone(),
            user_id,
            true,
            None, // recovery flow — no specific access token to invalidate; all_devices revokes refresh tokens
            None,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        // 4. Register new device directly (bypass PoW for recovery flow)
        let hostname = env::var("SERVER_HOSTNAME").unwrap_or_else(|_| "construct.cc".to_string());

        let verifying_key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.verifying_key,
        )
        .unwrap_or(public_keys.verifying_key.as_bytes().to_vec());

        let identity_public = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.identity_public,
        )
        .unwrap_or(public_keys.identity_public.as_bytes().to_vec());

        let signed_prekey_public = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.signed_prekey_public,
        )
        .unwrap_or(public_keys.signed_prekey_public.as_bytes().to_vec());

        let signed_prekey_signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.signed_prekey_signature,
        )
        .unwrap_or(public_keys.signed_prekey_signature.as_bytes().to_vec());

        // Verify SPK signature before registering (recovery path)
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
                identity_public,
                signed_prekey_public,
                signed_prekey_signature,
                crypto_suites: format!(r#"["{}"]"#, public_keys.crypto_suite),
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

        // 5. Generate tokens for new device
        let (access_token, _, exp_timestamp) = app_context
            .auth_manager
            .create_token_for_device(&user_id, Some(&new_device.device_id))
            .map_err(|e| Status::internal(e.to_string()))?;

        let (refresh_token, refresh_jti, _) = app_context
            .auth_manager
            .create_refresh_token_for_device(&user_id, Some(&new_device.device_id))
            .map_err(|e| Status::internal(e.to_string()))?;

        // Store refresh token
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

        // 6. Update last_recovery_at
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
                ice_bridge_cert: self.ice_bridge_cert.clone(),
            }),
            devices_revoked,
            recovered_at: now,
            warnings: vec!["All existing sessions have been terminated".to_string()],
            error: None,
        }))
    }

    // =========================================================================
    // Social Recovery Bundle RPCs (SLIP-39 Variant A — vault key)
    // =========================================================================

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

        // 1. Get server signer
        let signer = self.context.server_signer.as_ref().ok_or_else(|| {
            Status::unavailable(
                "sealed sender not available: federation signing key not configured",
            )
        })?;

        // 2. Authenticate: extract user_id from JWT
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {}", e)))?;
        let user_id = &claims.sub;

        // 3. Get device_id from x-device-id header
        let device_id = request
            .metadata()
            .get("x-device-id")
            .ok_or_else(|| Status::invalid_argument("x-device-id header required"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("invalid x-device-id header"))?
            .to_string();

        // 4. Look up device identity key from DB
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

        // 5. Build SenderCertificate
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + 86400; // 24 hours

        let domain = signer.instance_domain().to_string();

        // 6. Create canonical bytes for signing:
        // sender_user_id || sender_domain || sender_identity_key || sender_device_id || issued_at || expires_at
        let mut sign_payload = Vec::new();
        sign_payload.extend_from_slice(user_id.as_bytes());
        sign_payload.push(b':');
        sign_payload.extend_from_slice(domain.as_bytes());
        sign_payload.push(b':');
        sign_payload.extend_from_slice(&identity_key);
        sign_payload.push(b':');
        sign_payload.extend_from_slice(device_id.as_bytes());
        sign_payload.push(b':');
        sign_payload.extend_from_slice(now.to_string().as_bytes());
        sign_payload.push(b':');
        sign_payload.extend_from_slice(expires_at.to_string().as_bytes());

        let signature = signer.sign_bytes(&sign_payload);

        let cert = SenderCertificate {
            sender_user_id: user_id.to_string(),
            sender_domain: domain,
            sender_identity_key: identity_key,
            sender_device_id: device_id,
            issued_at: now,
            expires_at,
            server_signature: signature,
        };

        // 7. Serialize certificate to protobuf bytes
        let cert_bytes = cert.encode_to_vec();

        tracing::info!(
            user_id = %user_id,
            expires_at = %expires_at,
            "Issued sender certificate"
        );

        Ok(Response::new(proto::GetSenderCertificateResponse {
            certificate: cert_bytes,
            expires_at,
        }))
    }

    // =========================================================================
    // Flow B: Phone approves TUI device link
    // =========================================================================

    async fn approve_join_request(
        &self,
        request: Request<proto::ApproveJoinRequestRequest>,
    ) -> Result<Response<proto::ApproveJoinRequestResponse>, Status> {
        let token = request_token(request.metadata())?;
        let req = request.into_inner();

        if req.pending_device_id.is_empty() {
            return Err(Status::invalid_argument("pending_device_id is required"));
        }

        // Verify auth token
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        // Atomically consume the join request from Redis
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

        // Check device_id not already registered
        if construct_db::device_exists(self.context.db_pool.as_ref(), &req.pending_device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::already_exists("device_id already registered"));
        }

        // Decode keys
        let b64 = base64::engine::general_purpose::STANDARD;
        let decode = |s: &str, field: &str| {
            b64.decode(s)
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

        // Verify SPK signature before registering (device-join path)
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

        // Issue JWT for the new device
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

        // Store approved result in Redis so TUI can pick it up via polling
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
                ice_bridge_cert: self.ice_bridge_cert.clone(),
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

        // 1. Require TOKEN_ISSUER_KEY to be configured.
        let k_bytes = self
            .token_issuer_key
            .ok_or_else(|| Status::unavailable("privacy pass: token issuance not configured"))?;
        let k = Scalar::from_bytes_mod_order(k_bytes);

        // 2. Authenticate caller.
        let token = request_token(request.metadata())?;
        let claims = self
            .context
            .auth_manager
            .verify_token(&token)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {}", e)))?;
        let user_id = claims.sub.clone();

        // 3. Validate input: 1–20 blinded points, each exactly 32 bytes.
        let blinded_points = &request.get_ref().blinded_points;
        if blinded_points.is_empty() || blinded_points.len() > 20 {
            return Err(Status::invalid_argument(
                "blinded_points: must have 1–20 entries",
            ));
        }

        // 4. Rate-limit: max 20 tokens per hour per user.
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

        // 5. Evaluate OPRF: Z = k * blinded_point for each input.
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

        // 6. Produce DLEQ proof so client can verify server used the registered key.
        // For now we return the pubkey bytes alongside evaluated points.
        // Full batch DLEQ proof is Phase 2.1 (future work).
        let pubkey_point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * k;
        let pubkey_bytes = pubkey_point.compress().to_bytes().to_vec();

        Ok(Response::new(proto::IssueTokensResponse {
            evaluated_points,
            server_pubkey: pubkey_bytes,
        }))
    }
}

// =============================================================================
// DeviceService — manages device tokens and device-level operations
// =============================================================================

#[tonic::async_trait]
impl proto::device_service_server::DeviceService for AuthGrpcService {
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

        // current device_id lives in the JWT "jti" claim naming convention varies;
        // we don't store device_id in claims so skip is_current detection for now
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

        let stream = tokio_stream::iter(items);
        Ok(Response::new(Box::pin(stream)))
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

        // Verify the device belongs to this user
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
            // Revoke all sessions for the revoked device
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

    /// UpdatePushToken — upsert APNs/FCM token for the authenticated device.
    /// Writes to the same `device_tokens` table as NotificationService.RegisterDeviceToken.
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
        // PUSH_ENV_SANDBOX = 1 (debug builds), PUSH_ENV_PRODUCTION = 2 (release builds)
        let environment = match req.environment {
            2 => "production",
            _ => "sandbox", // 1 = sandbox, 0 = unspecified → default to sandbox
        };

        use construct_server_shared::apns::DeviceTokenEncryption;
        let token_hash = DeviceTokenEncryption::hash_token(&req.push_token);
        let token_encryption =
            DeviceTokenEncryption::from_hex(&self.context.config.apns.device_token_encryption_key)
                .map_err(|e| Status::internal(format!("Token encryption unavailable: {e}")))?;
        let token_encrypted = token_encryption
            .encrypt(&req.push_token)
            .map_err(|e| Status::internal(format!("Failed to encrypt token: {e}")))?;

        let db: &sqlx::PgPool = self.context.db_pool.as_ref();
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
        .execute(db)
        .await
        .map_err(|e| Status::internal(format!("DB error: {e}")))?;

        tracing::info!(
            device_id = %req.device_id,
            provider  = %provider,
            "Push token updated via DeviceService"
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

        let db: &sqlx::PgPool = self.context.db_pool.as_ref();
        let result =
            sqlx::query(r#"DELETE FROM device_tokens WHERE user_id = $1 AND device_id = $2"#)
                .bind(user_id)
                .bind(&req.device_id)
                .execute(db)
                .await
                .map_err(|e| Status::internal(format!("DB error: {e}")))?;

        tracing::info!(
            device_id = %req.device_id,
            removed   = result.rows_affected(),
            "Push token unregistered via DeviceService"
        );

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

        // Generate 32 random bytes encoded as base64url
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

// =============================================================================
// DeviceLinkService — unauthenticated endpoint for new device to complete link
// =============================================================================

#[tonic::async_trait]
impl proto::device_link_service_server::DeviceLinkService for AuthGrpcService {
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

        // Consume the link token (one-time use)
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

        // Check device_id not already registered
        if construct_db::device_exists(self.context.db_pool.as_ref(), &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::already_exists("device_id already registered"));
        }

        // Decode keys
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let decode = |s: &str, field: &str| {
            b64.decode(s)
                .map_err(|_| Status::invalid_argument(format!("invalid base64 in {}", field)))
        };

        let verifying_key = decode(&public_keys.verifying_key, "verifying_key")?;
        let identity_public = decode(&public_keys.identity_public, "identity_public")?;
        let signed_prekey_public =
            decode(&public_keys.signed_prekey_public, "signed_prekey_public")?;
        let signed_prekey_signature = decode(
            &public_keys.signed_prekey_signature,
            "signed_prekey_signature",
        )?;

        let hostname = self.context.config.instance_domain.clone();

        // Verify SPK signature before registering (device-link path)
        verify_spk_signature(
            &verifying_key,
            &signed_prekey_public,
            &signed_prekey_signature,
        )?;

        let device_data = construct_db::CreateDeviceData {
            device_id: req.device_id.clone(),
            server_hostname: hostname,
            verifying_key,
            identity_public,
            signed_prekey_public,
            signed_prekey_signature,
            crypto_suites: format!("[\"{}\"]", public_keys.crypto_suite),
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

        // Issue JWT for the new device
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

        tracing::info!(
            user_id = %user_id_str,
            device_id = %req.device_id,
            "Device linked successfully"
        );

        Ok(Response::new(proto::ConfirmDeviceLinkResponse {
            tokens: Some(proto::AuthTokensResponse {
                user_id: user_id_str,
                access_token,
                refresh_token,
                expires_at: exp_timestamp,
                ice_bridge_cert: self.ice_bridge_cert.clone(),
            }),
        }))
    }

    // =========================================================================
    // Flow B: TUI → Phone linking
    // =========================================================================

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

        // Check device_id not already registered
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

        tracing::info!(
            pending_device_id = %pending_device_id,
            "Join request stored (10 min TTL)"
        );

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

        // Check if approved first
        let approved_value = {
            let mut queue = self.context.queue.lock().await;
            queue
                .get_join_approved(&req.pending_device_id)
                .await
                .map_err(|e| Status::internal(format!("Redis error: {e}")))?
        };

        if let Some(value) = approved_value {
            // Parse: "{access_token}:{refresh_token}:{user_id}:{exp_timestamp}"
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
                        ice_bridge_cert: self.ice_bridge_cert.clone(),
                    }),
                }));
            }
        }

        // Check if join request still exists (pending)
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
            // Neither approved nor pending → expired (or never existed)
            proto::check_join_request_status_response::Status::Expired
        };

        Ok(Response::new(proto::CheckJoinRequestStatusResponse {
            status: status as i32,
            tokens: None,
        }))
    }
}

/// Extract Bearer token from gRPC metadata
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

/// GET /.well-known/jwks.json
/// Returns a proper JSON Web Key Set (JWKS) for our RS256 public key.
/// Envoy's `jwt_authn` filter fetches this to validate Bearer tokens and
/// inject `x-user-id` from the `sub` claim.
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

    // Normalize: env files often store newlines as literal \n
    let pem = raw.replace("\\n", "\n");

    // Accept both PKCS#8 ("BEGIN PUBLIC KEY") and PKCS#1 ("BEGIN RSA PUBLIC KEY")
    let public_key = rsa::RsaPublicKey::from_public_key_pem(&pem)
        .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(&pem));

    match public_key {
        Ok(key) => {
            // Encode modulus and exponent as base64url (no padding) — standard JWK format
            let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());

            let jwks = json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "construct-auth-key",
                    "n": n,
                    "e": e
                }]
            });
            (StatusCode::OK, Json(jwks))
        }
        Err(e) => {
            tracing::error!("Failed to parse JWT_PUBLIC_KEY for JWKS endpoint: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to parse JWT public key"})),
            )
        }
    }
}

/// GET /public-key
/// Returns the JWT public key in PEM format
/// This endpoint is public and doesn't require authentication
async fn get_public_key() -> impl IntoResponse {
    match env::var("JWT_PUBLIC_KEY") {
        Ok(public_key) => (StatusCode::OK, public_key),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "JWT public key not configured".to_string(),
        ),
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Service discovery endpoint
async fn well_known_construct_server(
    State(context): State<Arc<AuthServiceContext>>,
) -> impl IntoResponse {
    use axum::http::header;

    let app_context = Arc::new(context.to_app_context());

    let public_key = app_context
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    let domain = &app_context.config.instance_domain;
    let tls_enabled = public_key.is_some();

    let discovery_info = json!({
        "version": "1.0",
        "protocol": "grpc",
        "server": {
            "domain": domain,
            "version": env!("CARGO_PKG_VERSION"),
            "public_key": public_key,
        },
        "grpc_endpoint": format!("{}:443", domain),
        "services": [
            "auth.AuthService",
            "user.UserService",
            "messaging.MessagingService",
            "notification.NotificationService",
            "invite.InviteService",
            "media.MediaService"
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

    info!("=== Auth Service Starting ===");
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
    let auth_manager = Arc::new(
        construct_server_shared::auth::AuthManager::new(&config)
            .context("Failed to initialize auth manager")?,
    );

    // Initialize Key Management System (optional, requires VAULT_ADDR)
    let key_management =
        match construct_server_shared::key_management::KeyManagementConfig::from_env() {
            Ok(kms_config) => {
                info!("Initializing Key Management System...");
                match construct_server_shared::key_management::KeyManagementSystem::new(
                    db_pool.clone(),
                    kms_config,
                )
                .await
                {
                    Ok(kms) => {
                        // Start background tasks (key refresh, rotation)
                        if let Err(e) = kms.start().await {
                            tracing::error!(error = %e, "Failed to start key management background tasks");
                            return Err(e).context("Failed to start key management system");
                        }
                        info!("Key Management System initialized and started");
                        Some(Arc::new(kms))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to initialize Key Management System - continuing without automatic key rotation"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "Key Management System disabled (VAULT_ADDR not configured or invalid config)"
                );
                None
            }
        };

    // Initialize server signer for sealed sender certificates
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

    // Create service context
    let context = Arc::new(AuthServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
        key_management,
        server_signer,
    });

    // handlers module is local (auth-service/src/handlers.rs)

    // Compute ICE bridge cert once at startup (shared across all gRPC connections).
    // Requires ICE_ENABLED=true and ICE_SERVER_KEY to be set (same as gateway).
    let ice_bridge_cert: Option<String> = if config.ice_enabled {
        config.ice_server_key.as_ref().and_then(|key_b64| {
            let bytes = b64::STANDARD.decode(key_b64)
                .map_err(|e| tracing::warn!(error = %e, "ICE_SERVER_KEY: invalid base64 — bridge cert will not be included in auth responses"))
                .ok()?;
            let server_cfg = construct_ice::ServerConfig::from_bytes(&bytes)
                .map_err(|e| tracing::warn!(error = %e, "ICE_SERVER_KEY: failed to parse — bridge cert will not be included in auth responses"))
                .ok()?;
            let cert = server_cfg.bridge_cert();
            info!(cert = %cert, "ICE bridge cert ready — will be included in auth responses");
            Some(cert)
        })
    } else {
        None
    };

    // Start gRPC AuthService (hard-cut target transport)
    let grpc_context = context.clone();
    let grpc_ice_bridge_cert = ice_bridge_cert.clone();

    // Load Privacy Pass token issuer key (optional — feature disabled if absent).
    let token_issuer_key: Option<[u8; 32]> = match env::var("TOKEN_ISSUER_KEY") {
        Ok(hex) => {
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>();
            match bytes {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    info!("Privacy Pass token issuer key loaded — IssueTokens enabled");
                    Some(arr)
                }
                _ => {
                    tracing::warn!("TOKEN_ISSUER_KEY: must be 64 hex chars — IssueTokens disabled");
                    None
                }
            }
        }
        Err(_) => {
            info!("TOKEN_ISSUER_KEY not set — IssueTokens disabled");
            None
        }
    };

    let grpc_bind_address =
        env::var("AUTH_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50051".to_string());
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_address).await?;
    let grpc_keepalive_secs = config.grpc_keepalive_interval_secs;
    let grpc_keepalive_timeout_secs = config.grpc_keepalive_timeout_secs;
    tokio::spawn(async move {
        let service = AuthGrpcService {
            context: grpc_context,
            ice_bridge_cert: grpc_ice_bridge_cert,
            token_issuer_key,
        };
        if let Err(e) =
            construct_server_shared::grpc_server(grpc_keepalive_secs, grpc_keepalive_timeout_secs)
                .add_service(AuthServiceServer::new(service.clone()))
                .add_service(DeviceServiceServer::new(service.clone()))
                .add_service(DeviceLinkServiceServer::new(service))
                .serve_with_incoming_shutdown(
                    grpc_incoming,
                    construct_server_shared::shutdown_signal(),
                )
                .await
        {
            tracing::error!(error = %e, "Auth gRPC server failed");
        }
    });
    info!("Auth gRPC listening on {}", grpc_bind_address);

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
        .route(
            "/.well-known/construct-server",
            get(well_known_construct_server),
        )
        // Public key endpoint (no auth required)
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/public-key", get(get_public_key))
        // Passwordless authentication endpoints
        .route("/api/v1/auth/challenge", get(handlers::get_pow_challenge))
        .route(
            "/api/v1/auth/register-device",
            post(handlers::register_device),
        )
        .route("/api/v1/auth/device", post(handlers::authenticate_device))
        // Token management endpoints
        .route("/api/v1/auth/refresh", post(handlers::refresh_token))
        .route("/api/v1/auth/logout", post(handlers::logout))
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("Auth Service listening on {}", config.bind_address);

    let listener = construct_server_shared::mptcp_or_tcp_listener(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start server")?;

    Ok(())
}

/// Verify the Ed25519 SPK signature.
/// Message = "KonstruktX3DH-v1" || [0x00, 0x01] (ClassicX25519) || signed_prekey_public
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
    msg.extend_from_slice(&[0x00, 0x01]); // ClassicX25519
    msg.extend_from_slice(signed_prekey_public);
    vk.verify(&msg, &sig)
        .map_err(|_| Status::invalid_argument("signed_prekey_signature verification failed"))
}
