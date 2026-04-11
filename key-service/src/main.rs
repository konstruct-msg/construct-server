// ============================================================================
// Key Service - E2EE Key Management
// ============================================================================
//
// Pre-key management service for X3DH key exchange protocol.
// Handles:
// - Pre-key bundles for initiating encrypted sessions
// - One-time pre-key upload and distribution
// - Signed pre-key rotation
// - Identity key verification
//
// Architecture:
// - Stateless handlers (database stores all keys)
// - Server NEVER has access to private keys
// - All keys stored are PUBLIC keys only
//
// ============================================================================

mod core;

use anyhow::{Context, Result};
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey as Ed25519VerifyingKey};
use redis::aio::ConnectionManager as RedisConnectionManager;
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    key_service_server::{KeyService, KeyServiceServer},
    SendBlindNotificationRequest,
};

/// Notify the device owner to replenish one-time prekeys when supply is low.
/// - `otp_was_consumed = false` means keys were already exhausted before this request.
/// - `otp_was_consumed = true`  means one key was just consumed; we check the remaining count.
const LOW_PREKEY_THRESHOLD: u32 = 5;

// ============================================================================
// Service Context
// ============================================================================

struct KeyServiceContext {
    db: sqlx::PgPool,
    notification_client: Option<NotificationClient>,
    redis: RedisConnectionManager,
    /// Optional server Ed25519 key for signing pre-key bundles.
    /// `None` when `BUNDLE_SIGNING_KEY` env var is not set (dev/test).
    bundle_signing_key: Option<SigningKey>,
    /// Base64-encoded verifying key for `/.well-known/construct-server`.
    /// `None` when bundle signing is disabled.
    bundle_verifying_key_b64: Option<String>,
}

impl KeyServiceContext {
    async fn new() -> Result<Self> {
        let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

        let db = sqlx::PgPool::connect(&database_url)
            .await
            .context("Failed to connect to database")?;

        let redis_url = env::var("REDIS_URL").context("REDIS_URL must be set")?;
        let redis_client = redis::Client::open(redis_url).context("Failed to open Redis client")?;
        let redis = RedisConnectionManager::new(redis_client)
            .await
            .context("Failed to connect to Redis")?;

        let notification_client = env::var("NOTIFICATION_SERVICE_URL")
            .ok()
            .and_then(|url| match NotificationClient::new(&url) {
                Ok(c) => {
                    info!("Notification service client configured (low-prekey alerts enabled)");
                    Some(c)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to create notification client — low-prekey alerts disabled");
                    None
                }
            });

        // Optional server bundle signing key
        let bundle_signing_key = match env::var("BUNDLE_SIGNING_KEY") {
            Ok(b64) => match BASE64.decode(b64.trim()) {
                Ok(bytes) => {
                    let arr: Result<[u8; 32], _> = bytes.try_into();
                    match arr {
                        Ok(seed) => {
                            let sk = SigningKey::from_bytes(&seed);
                            info!("Bundle signing key loaded — bundles will be server-signed");
                            Some(sk)
                        }
                        Err(_) => {
                            tracing::warn!(
                                "BUNDLE_SIGNING_KEY must be 32 bytes — bundle signing disabled"
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to decode BUNDLE_SIGNING_KEY — bundle signing disabled");
                    None
                }
            },
            Err(_) => {
                tracing::info!("BUNDLE_SIGNING_KEY not set — bundle signing disabled");
                None
            }
        };

        Ok(Self {
            db,
            notification_client,
            redis,
            bundle_verifying_key_b64: bundle_signing_key
                .as_ref()
                .map(|sk| BASE64.encode(Ed25519VerifyingKey::from(sk).to_bytes())),
            bundle_signing_key,
        })
    }
}

// ============================================================================
// gRPC Service Implementation
// ============================================================================

/// Extract the caller's device_id from gRPC metadata (set by Envoy/gateway).
fn extract_device_id<T>(req: &Request<T>) -> Option<String> {
    req.metadata()
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Clone)]
struct KeyGrpcService {
    context: Arc<KeyServiceContext>,
}

#[tonic::async_trait]
impl KeyService for KeyGrpcService {
    // =========================================================================
    // Pre-Key Bundle Operations
    // =========================================================================

    async fn get_pre_key_bundle(
        &self,
        request: Request<proto::GetPreKeyBundleRequest>,
    ) -> Result<Response<proto::GetPreKeyBundleResponse>, Status> {
        // Rate limit: max 10 bundle requests per minute per (caller_device, target_user) pair.
        // This prevents OTPK exhaustion attacks where an attacker drains all one-time pre-keys,
        // degrading forward-secrecy for the target.
        let caller_device = extract_device_id(&request).unwrap_or_else(|| "anonymous".to_string());
        let req = request.into_inner();

        if req.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        {
            // Atomic INCR + EXPIRE via Lua — prevents the race condition where a crash
            // between the two commands leaves the key without a TTL (permanent block).
            // Fails closed: Redis unavailable → deny the request (OTPK exhaustion safety).
            const RATE_LIMIT_LUA: &str = r#"
                local count = redis.call('INCR', KEYS[1])
                if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
                return count
            "#;
            let mut redis = self.context.redis.clone();
            let rate_key = format!("rate:bundle:{}:{}", caller_device, req.user_id);
            let count: i64 = redis::Script::new(RATE_LIMIT_LUA)
                .key(&rate_key)
                .arg(60i64) // 60-second window
                .invoke_async(&mut redis)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "Redis unavailable for bundle rate-limit — failing closed");
                    Status::unavailable("Service temporarily unavailable")
                })?;
            if count > 10 {
                return Err(Status::resource_exhausted(
                    "Too many bundle requests — try again later",
                ));
            }
        }

        let bundle = core::get_prekey_bundle(
            &self.context.db,
            &req.user_id,
            req.device_id.as_deref(),
            self.context.bundle_signing_key.as_ref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        match bundle {
            Some(b) => {
                // Capture for low-prekey check before b is moved into the response.
                let otp_was_consumed = b.one_time_prekey_id.is_some();
                let notify_device_id = b.device_id.clone();
                let notify_user_id = req.user_id.clone();

                let response = Response::new(proto::GetPreKeyBundleResponse {
                    bundle: Some(proto::PreKeyBundle {
                        registration_id: 1,
                        identity_key: b.identity_key,
                        signed_pre_key: b.signed_prekey,
                        signed_pre_key_id: b.signed_prekey_id,
                        signed_pre_key_signature: b.signed_prekey_signature,
                        one_time_pre_key: b.one_time_prekey,
                        one_time_pre_key_id: b.one_time_prekey_id,
                        crypto_suite: b.crypto_suite,
                        generated_at: b.registered_at.timestamp(),
                        kyber_pre_key: b.kyber_pre_key,
                        kyber_pre_key_id: b.kyber_pre_key_id,
                        kyber_pre_key_signature: b.kyber_pre_key_signature,
                        kyber_one_time_pre_key: b.kyber_one_time_pre_key,
                        kyber_one_time_pre_key_id: b.kyber_one_time_pre_key_id,
                        spk_uploaded_at: b.spk_uploaded_at.map(|t| t.timestamp()).unwrap_or(0),
                        spk_rotation_epoch: b.spk_rotation_epoch,
                        kyber_spk_uploaded_at: b.kyber_spk_uploaded_at.map(|t| t.timestamp()),
                        kyber_spk_rotation_epoch: b.kyber_spk_rotation_epoch.into(),
                        bundle_signature: b.bundle_signature.unwrap_or_default(),
                    }),
                    device_id: b.device_id,
                    has_one_time_key: otp_was_consumed,
                    verifying_key: b.verifying_key,
                });
                if let Some(notif_client) = self.context.notification_client.clone() {
                    let db = self.context.db.clone();
                    tokio::spawn(async move {
                        maybe_notify_low_prekeys(
                            &db,
                            &notif_client,
                            &notify_user_id,
                            &notify_device_id,
                            otp_was_consumed,
                        )
                        .await;
                    });
                }

                Ok(response)
            }
            None => Err(Status::not_found("User or device not found")),
        }
    }

    // =========================================================================
    // One-Time Pre-Key Management
    // =========================================================================

    async fn upload_pre_keys(
        &self,
        request: Request<proto::UploadPreKeysRequest>,
    ) -> Result<Response<proto::UploadPreKeysResponse>, Status> {
        // Validate that the device_id in the request body matches the authenticated device.
        // x-device-id is injected by the gateway after JWT verification — trust it as the
        // source of truth and reject any request claiming a different device identity.
        let authed_device_id = extract_device_id(&request)
            .ok_or_else(|| Status::unauthenticated("x-device-id header missing"))?;

        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if req.device_id != authed_device_id {
            return Err(Status::permission_denied(
                "device_id does not match authenticated device",
            ));
        }
        if req.pre_keys.is_empty() && req.kyber_pre_keys.is_empty() {
            return Err(Status::invalid_argument(
                "pre_keys or kyber_pre_keys cannot both be empty",
            ));
        }

        // Convert proto prekeys to core types
        let prekeys: Vec<core::OneTimePreKey> = req
            .pre_keys
            .into_iter()
            .map(|k| core::OneTimePreKey {
                key_id: k.key_id,
                public_key: k.public_key,
            })
            .collect();

        // Convert proto Kyber prekeys to core types
        let kyber_prekeys: Vec<core::KyberOneTimePreKey> = req
            .kyber_pre_keys
            .into_iter()
            .map(|k| core::KyberOneTimePreKey {
                key_id: k.key_id,
                public_key: k.public_key,
                signature: k.signature,
            })
            .collect();

        let (classic_count, kyber_count) = core::upload_prekeys(
            &self.context.db,
            &req.device_id,
            &prekeys,
            req.replace_existing,
            &kyber_prekeys,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        // Handle optional classic signed prekey update
        if let Some(spk) = req.signed_pre_key {
            let signed_key = core::SignedPreKey {
                key_id: spk.key_id,
                public_key: spk.public_key,
                signature: spk.signature,
            };
            core::rotate_signed_prekey(&self.context.db, &req.device_id, &signed_key, "upload")
                .await
                .map(|_| ())
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        // Handle optional Kyber signed prekey update
        if let Some(kspk) = req.kyber_signed_pre_key {
            core::upload_kyber_signed_prekey(
                &self.context.db,
                &req.device_id,
                kspk.key_id,
                &kspk.public_key,
                &kspk.signature,
            )
            .await
            .map(|_| ())
            .map_err(|e| Status::internal(e.to_string()))?;
        }

        Ok(Response::new(proto::UploadPreKeysResponse {
            success: true,
            pre_key_count: classic_count,
            uploaded_at: chrono::Utc::now().timestamp(),
            kyber_pre_key_count: kyber_count,
        }))
    }

    async fn get_pre_key_count(
        &self,
        request: Request<proto::GetPreKeyCountRequest>,
    ) -> Result<Response<proto::GetPreKeyCountResponse>, Status> {
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let (count, last_upload) = core::get_prekey_count(&self.context.db, &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::GetPreKeyCountResponse {
            count,
            recommended_minimum: 20,
            last_upload_at: last_upload.timestamp(),
        }))
    }

    // =========================================================================
    // Signed Pre-Key Rotation
    // =========================================================================

    async fn rotate_signed_pre_key(
        &self,
        request: Request<proto::RotateSignedPreKeyRequest>,
    ) -> Result<Response<proto::RotateSignedPreKeyResponse>, Status> {
        let authed_device_id = extract_device_id(&request)
            .ok_or_else(|| Status::unauthenticated("x-device-id header missing"))?;

        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if req.device_id != authed_device_id {
            return Err(Status::permission_denied(
                "device_id does not match authenticated device",
            ));
        }

        let new_key = req
            .new_signed_pre_key
            .ok_or_else(|| Status::invalid_argument("new_signed_pre_key is required"))?;

        if new_key.public_key.is_empty() || new_key.signature.is_empty() {
            return Err(Status::invalid_argument(
                "public_key and signature are required",
            ));
        }

        let reason = match req.reason {
            1 => "scheduled",
            2 => "security",
            3 => "user",
            4 => "reinstall",
            _ => "unspecified",
        };

        let signed_key = core::SignedPreKey {
            key_id: new_key.key_id,
            public_key: new_key.public_key,
            signature: new_key.signature,
        };

        let (old_valid_until, new_spk_rotation_epoch) =
            core::rotate_signed_prekey(&self.context.db, &req.device_id, &signed_key, reason)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        // Rotate Kyber SPK if provided in the same request (keeps both keys in sync)
        let (new_kyber_key_id, new_kyber_spk_rotation_epoch) =
            if let Some(kspk) = req.new_kyber_signed_pre_key {
                let key_id = kspk.key_id;
                let epoch = core::upload_kyber_signed_prekey(
                    &self.context.db,
                    &req.device_id,
                    key_id,
                    &kspk.public_key,
                    &kspk.signature,
                )
                .await
                .map_err(|e| Status::internal(format!("Kyber SPK rotation failed: {e}")))?;
                (Some(key_id), Some(epoch))
            } else {
                (None, None)
            };

        Ok(Response::new(proto::RotateSignedPreKeyResponse {
            success: true,
            new_key_id: signed_key.key_id,
            old_key_valid_until: old_valid_until.timestamp(),
            rotated_at: chrono::Utc::now().timestamp(),
            new_kyber_key_id,
            new_spk_rotation_epoch,
            new_kyber_spk_rotation_epoch,
        }))
    }

    async fn get_signed_pre_key_age(
        &self,
        request: Request<proto::GetSignedPreKeyAgeRequest>,
    ) -> Result<Response<proto::GetSignedPreKeyAgeResponse>, Status> {
        let req = request.into_inner();

        if req.device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let result = core::get_signed_prekey_age(&self.context.db, &req.device_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        match result {
            Some((key_id, uploaded_at, should_rotate)) => {
                let age = chrono::Utc::now() - uploaded_at;
                Ok(Response::new(proto::GetSignedPreKeyAgeResponse {
                    key_id,
                    uploaded_at: uploaded_at.timestamp(),
                    age_seconds: age.num_seconds(),
                    should_rotate,
                    rotation_interval: 30 * 24 * 60 * 60, // 30 days
                }))
            }
            None => Err(Status::not_found("Device not found")),
        }
    }

    // =========================================================================
    // Identity Key Operations
    // =========================================================================

    async fn get_identity_key(
        &self,
        request: Request<proto::GetIdentityKeyRequest>,
    ) -> Result<Response<proto::GetIdentityKeyResponse>, Status> {
        let req = request.into_inner();

        if req.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let result =
            core::get_identity_key(&self.context.db, &req.user_id, req.device_id.as_deref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        match result {
            Some((identity_key, first_seen)) => {
                // Calculate fingerprint (first 32 chars of hex)
                let fingerprint = hex::encode(&identity_key)
                    .chars()
                    .take(32)
                    .collect::<Vec<_>>()
                    .chunks(4)
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_uppercase();

                Ok(Response::new(proto::GetIdentityKeyResponse {
                    identity_key,
                    fingerprint,
                    first_seen_at: first_seen.timestamp(),
                    key_changed: false, // TODO: track key changes
                    previous_fingerprint: None,
                }))
            }
            None => Err(Status::not_found("User or device not found")),
        }
    }

    async fn verify_safety_number(
        &self,
        request: Request<proto::VerifySafetyNumberRequest>,
    ) -> Result<Response<proto::VerifySafetyNumberResponse>, Status> {
        let req = request.into_inner();

        if req.our_user_id.is_empty() || req.their_user_id.is_empty() {
            return Err(Status::invalid_argument(
                "our_user_id and their_user_id are required",
            ));
        }
        if req.expected_safety_number.is_empty() {
            return Err(Status::invalid_argument(
                "expected_safety_number is required",
            ));
        }

        // Get both identity keys
        let our_key = core::get_identity_key(&self.context.db, &req.our_user_id, None)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("Our user not found"))?;

        let their_key = core::get_identity_key(&self.context.db, &req.their_user_id, None)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("Their user not found"))?;

        // Calculate safety number
        let actual = core::calculate_safety_number(
            &our_key.0,
            &their_key.0,
            &req.our_user_id,
            &req.their_user_id,
        );

        let matches = actual.replace(" ", "") == req.expected_safety_number.replace(" ", "");

        Ok(Response::new(proto::VerifySafetyNumberResponse {
            matches,
            actual_safety_number: actual,
            verified_at: chrono::Utc::now().timestamp(),
        }))
    }

    // =========================================================================
    // Batch Operations
    // =========================================================================

    async fn get_pre_key_bundles(
        &self,
        request: Request<proto::GetPreKeyBundlesRequest>,
    ) -> Result<Response<proto::GetPreKeyBundlesResponse>, Status> {
        let req = request.into_inner();

        if req.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let device_ids = if req.device_ids.is_empty() {
            None
        } else {
            Some(req.device_ids.as_slice())
        };

        let (bundles, unavailable) = core::get_prekey_bundles(
            &self.context.db,
            &req.user_id,
            device_ids,
            self.context.bundle_signing_key.as_ref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        // Collect per-device info for low-prekey check before consuming the iterator.
        let notify_items: Vec<(String, bool)> = if self.context.notification_client.is_some() {
            bundles
                .iter()
                .map(|b| (b.device_id.clone(), b.one_time_prekey_id.is_some()))
                .collect()
        } else {
            vec![]
        };

        let proto_bundles = bundles
            .into_iter()
            .map(|b| proto::DevicePreKeyBundle {
                device_id: b.device_id.clone(),
                bundle: Some(proto::PreKeyBundle {
                    registration_id: 1,
                    identity_key: b.identity_key,
                    signed_pre_key: b.signed_prekey,
                    signed_pre_key_id: b.signed_prekey_id,
                    signed_pre_key_signature: b.signed_prekey_signature,
                    one_time_pre_key: b.one_time_prekey,
                    one_time_pre_key_id: b.one_time_prekey_id,
                    crypto_suite: b.crypto_suite,
                    generated_at: b.registered_at.timestamp(),
                    kyber_pre_key: b.kyber_pre_key,
                    kyber_pre_key_id: b.kyber_pre_key_id,
                    kyber_pre_key_signature: b.kyber_pre_key_signature,
                    kyber_one_time_pre_key: b.kyber_one_time_pre_key,
                    kyber_one_time_pre_key_id: b.kyber_one_time_pre_key_id,
                    spk_uploaded_at: b.spk_uploaded_at.map(|t| t.timestamp()).unwrap_or(0),
                    spk_rotation_epoch: b.spk_rotation_epoch,
                    kyber_spk_uploaded_at: b.kyber_spk_uploaded_at.map(|t| t.timestamp()),
                    kyber_spk_rotation_epoch: b.kyber_spk_rotation_epoch.into(),
                    bundle_signature: b.bundle_signature.unwrap_or_default(),
                }),
                platform: 0, // Unknown
            })
            .collect();

        // Fire-and-forget low-prekey checks for each device.
        if let Some(notif_client) = self.context.notification_client.clone() {
            let db = self.context.db.clone();
            let user_id = req.user_id.clone();
            tokio::spawn(async move {
                for (device_id, otp_was_consumed) in notify_items {
                    maybe_notify_low_prekeys(
                        &db,
                        &notif_client,
                        &user_id,
                        &device_id,
                        otp_was_consumed,
                    )
                    .await;
                }
            });
        }

        Ok(Response::new(proto::GetPreKeyBundlesResponse {
            bundles: proto_bundles,
            unavailable_devices: unavailable,
        }))
    }
}

// ============================================================================
// Low-Prekey Notification Helper
// ============================================================================

/// Sends a `replenish_prekeys` blind notification to `user_id` when their
/// device's one-time prekey supply drops below [`LOW_PREKEY_THRESHOLD`].
///
/// - `otp_was_consumed = false`: the prekey store was already empty before this
///   request — notify immediately.
/// - `otp_was_consumed = true`: one key was just consumed — query the remaining
///   count and notify only if it is below the threshold.
async fn maybe_notify_low_prekeys(
    db: &sqlx::PgPool,
    notif_client: &NotificationClient,
    user_id: &str,
    device_id: &str,
    otp_was_consumed: bool,
) {
    let should_notify = if !otp_was_consumed {
        true
    } else {
        match core::get_prekey_count(db, device_id).await {
            Ok((count, _)) => count < LOW_PREKEY_THRESHOLD,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    device_id,
                    "Failed to read prekey count for low-prekey check"
                );
                false
            }
        }
    };

    if should_notify {
        let mut client = notif_client.get();
        match client
            .send_blind_notification(SendBlindNotificationRequest {
                user_id: user_id.to_string(),
                badge_count: None,
                activity_type: Some("replenish_prekeys".to_string()),
                conversation_id: None,
            })
            .await
        {
            Ok(_) => tracing::info!(
                user_id,
                device_id,
                exhausted = !otp_was_consumed,
                "Low-prekey replenishment notification sent"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                user_id,
                device_id,
                "Failed to send low-prekey replenishment notification"
            ),
        }
    }
}

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "key-service",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn readiness_check(ctx: axum::extract::State<Arc<KeyServiceContext>>) -> impl IntoResponse {
    // Check database connection
    match sqlx::query("SELECT 1").fetch_one(&ctx.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready", "reason": "database unavailable" })),
        ),
    }
}

/// `GET /.well-known/construct-server`
///
/// Returns server metadata including the Ed25519 public key used to sign pre-key bundles.
/// Clients use this to verify `bundle_signature` on every received bundle.
async fn well_known(ctx: axum::extract::State<Arc<KeyServiceContext>>) -> impl IntoResponse {
    let domain = env::var("INSTANCE_DOMAIN").unwrap_or_else(|_| "construct.cc".to_string());
    match &ctx.bundle_verifying_key_b64 {
        Some(vk_b64) => (
            StatusCode::OK,
            Json(json!({
                "domain": domain,
                "bundle_signing_key": vk_b64,
                "bundle_signing_algorithm": "Ed25519",
                "version": env!("CARGO_PKG_VERSION")
            })),
        ),
        None => (
            StatusCode::OK,
            Json(json!({
                "domain": domain,
                "bundle_signing_key": null,
                "bundle_signing_algorithm": null,
                "version": env!("CARGO_PKG_VERSION")
            })),
        ),
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Key Service v{}", env!("CARGO_PKG_VERSION"));

    // Initialize context
    let context = Arc::new(KeyServiceContext::new().await?);

    // Create gRPC service
    let grpc_service = KeyGrpcService {
        context: context.clone(),
    };

    // gRPC server
    let grpc_addr: SocketAddr = env::var("KEY_SERVICE_GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50057".to_string())
        .parse()
        .context("Invalid KEY_SERVICE_GRPC_ADDR")?;

    info!("gRPC server listening on {}", grpc_addr);

    let grpc_server = construct_server_shared::grpc_server(
        std::env::var("GRPC_KEEPALIVE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(45),
    )
    .add_service(KeyServiceServer::new(grpc_service))
    .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal());

    // HTTP health server
    let http_addr: SocketAddr = env::var("KEY_SERVICE_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8057".to_string())
        .parse()
        .context("Invalid KEY_SERVICE_HTTP_ADDR")?;

    let http_app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/.well-known/construct-server", get(well_known))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        )
        .with_state(context)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    info!("HTTP health server listening on {}", http_addr);

    let http_server = axum::serve(tokio::net::TcpListener::bind(http_addr).await?, http_app);

    // Run both servers, shutdown gracefully on SIGTERM/Ctrl-C
    tokio::select! {
        result = grpc_server => {
            result.context("gRPC server error")?;
        }
        result = http_server => {
            result.context("HTTP server error")?;
        }
        _ = construct_server_shared::shutdown_signal() => {
            info!("Shutdown signal received, stopping key-service...");
        }
    }

    Ok(())
}
