use std::sync::Arc;

use crate::devices;
use axum::Json;
use chrono::Utc;
use construct_context::AppContext;
use construct_error::AppError;
use construct_metrics::AUTH_FAILURES_TOTAL;
use construct_utils::log_safe_id;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RefreshTokenResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct DevicePublicKeysInput {
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub crypto_suite: String,
    /// Client-declared support for SuiteID::PQ_RATCHET (sparse continuous PQ ratchet).
    pub supports_pq_ratchet: bool,
}

#[derive(Debug, Clone)]
pub struct PowSolutionInput {
    pub challenge: String,
    pub nonce: u64,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct RegisterDeviceInput {
    pub username: Option<String>,
    pub device_id: String,
    pub public_keys: DevicePublicKeysInput,
    pub pow_solution: PowSolutionInput,
    /// Identity public key for global user identity (Epic E).
    /// 32 bytes for Ed25519 (type 1). Should be provided by new clients.
    pub identity_public_key: Option<Vec<u8>>,
    /// Key algorithm type: 1=Ed25519, 2=ML-DSA-65, 3=Hybrid.
    /// Defaults to 1 (Ed25519) when identity_public_key is present.
    pub identity_key_type: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AuthenticateDeviceInput {
    pub device_id: String,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: i64,
}

pub async fn refresh_tokens(
    app_context: Arc<AppContext>,
    refresh_token: &str,
) -> Result<RefreshTokenResult, AppError> {
    // 1. Verify refresh token signature and expiry
    let claims = app_context
        .auth_manager
        .verify_token(refresh_token)
        .map_err(|e| {
            tracing::warn!(error = %e, "Invalid refresh token");
            AUTH_FAILURES_TOTAL
                .with_label_values(&["invalid_token"])
                .inc();
            AppError::Auth("Invalid or expired refresh token".to_string())
        })?;

    // 2. Create the new tokens BEFORE touching Redis so that if token generation
    //    fails we haven't consumed the old token yet.
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user ID in refresh token".to_string()))?;

    let (new_access_token, _access_jti, access_expires) = app_context
        .auth_manager
        .create_token_for_device(&user_id, claims.device_id.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (new_refresh_token, refresh_jti, _refresh_expires) = app_context
        .auth_manager
        .create_refresh_token_for_device(&user_id, claims.device_id.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    // 3. Atomically consume the old token and store the new one in a single
    //    Redis Lua script — eliminates the crash window between DEL and SET.
    let refresh_ttl_seconds =
        app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

    let user_id_from_token = {
        let mut queue = app_context.queue.lock().await;
        match queue
            .rotate_refresh_token(
                &claims.jti,
                &refresh_jti,
                &user_id.to_string(),
                refresh_ttl_seconds,
            )
            .await
        {
            Ok(Some(uid)) => uid,
            Ok(None) => {
                tracing::warn!(
                    jti = %claims.jti,
                    user_hash = %log_safe_id(&claims.sub, &app_context.config.logging.hash_salt),
                    "Refresh token was already used or revoked"
                );
                AUTH_FAILURES_TOTAL
                    .with_label_values(&["refresh_token_consumed"])
                    .inc();
                return Err(AppError::Auth(
                    "Refresh token was already used or revoked".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to rotate refresh token — fail closed");
                AUTH_FAILURES_TOTAL
                    .with_label_values(&["redis_unavailable"])
                    .inc();
                return Err(AppError::Auth("Cannot verify refresh token".to_string()));
            }
        }
    };

    // 4. Defense-in-depth: verify user_id in Redis matches JWT sub
    if user_id_from_token != claims.sub {
        tracing::error!(
            jti = %claims.jti,
            token_user_id = %claims.sub,
            redis_user_id = %user_id_from_token,
            "User ID mismatch between JWT and Redis"
        );
        AUTH_FAILURES_TOTAL
            .with_label_values(&["token_validation_failed"])
            .inc();
        return Err(AppError::Auth("Token validation failed".to_string()));
    }

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Token refreshed successfully"
    );

    Ok(RefreshTokenResult {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        expires_at: access_expires,
    })
}

pub async fn get_pow_challenge(
    app_context: Arc<AppContext>,
    headers: axum::http::HeaderMap,
) -> Result<(axum::http::HeaderMap, Json<devices::ChallengeResponse>), AppError> {
    devices::get_pow_challenge(axum::extract::State(app_context), headers).await
}

pub async fn register_device(
    app_context: Arc<AppContext>,
    headers: axum::http::HeaderMap,
    input: RegisterDeviceInput,
) -> Result<
    (
        axum::http::StatusCode,
        Json<devices::RegisterDeviceResponse>,
    ),
    AppError,
> {
    devices::register_device_core(
        app_context,
        headers,
        input.username,
        input.device_id,
        devices::DevicePublicKeysBinary {
            verifying_key: input.public_keys.verifying_key,
            identity_public: input.public_keys.identity_public,
            signed_prekey_public: input.public_keys.signed_prekey_public,
            signed_prekey_signature: input.public_keys.signed_prekey_signature,
            crypto_suite: input.public_keys.crypto_suite,
            supports_pq_ratchet: input.public_keys.supports_pq_ratchet,
        },
        devices::PowSolution {
            challenge: input.pow_solution.challenge,
            nonce: input.pow_solution.nonce,
            hash: input.pow_solution.hash,
        },
        input.identity_public_key,
        input.identity_key_type,
    )
    .await
}

pub async fn authenticate_device(
    app_context: Arc<AppContext>,
    input: AuthenticateDeviceInput,
) -> Result<
    (
        axum::http::StatusCode,
        Json<devices::RegisterDeviceResponse>,
    ),
    AppError,
> {
    devices::authenticate_device_core(
        app_context,
        input.device_id,
        input.timestamp,
        input.signature,
    )
    .await
}

pub async fn logout_user(
    app_context: Arc<AppContext>,
    user_id: Uuid,
    all_devices: bool,
    access_jti: Option<&str>,
    access_exp: Option<i64>,
    device_id: Option<&str>,
) -> Result<(), AppError> {
    // Invalidate the current access token so it cannot be reused after logout.
    // TTL is set to the token's remaining lifetime so the entry self-expires.
    // Fail closed: if we cannot write the blocklist, the access token remains
    // valid — returning success would lie to the client about session end.
    if let (Some(jti), Some(exp)) = (access_jti, access_exp) {
        let remaining = (exp - Utc::now().timestamp()).max(0);
        if remaining > 0 {
            let mut queue = app_context.queue.lock().await;
            queue.invalidate_access_token(jti, remaining).await.map_err(|e| {
                tracing::error!(error = %e, "Failed to add access token to blocklist — fail closed");
                AppError::internal("Cannot complete logout (token blocklist unavailable)")
            })?;
        }
    }

    if all_devices {
        let mut queue = app_context.queue.lock().await;
        queue
            .revoke_all_user_tokens(&user_id.to_string())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to revoke all user tokens — fail closed");
                AppError::internal("Cannot complete logout (refresh token revoke failed)")
            })?;
        drop(queue);

        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Logged out from all devices"
        );
    } else {
        // Single-device sign-out. For a *secondary* (linked) device this also
        // unregisters it (Signal-like) so it stops appearing in ListDevices and
        // can no longer authenticate — the fix for "logout leaves a ghost".
        // The user's *primary* device is never deactivated here: it owns the
        // account (passwordless identity), so deactivating it would look like
        // account loss.
        // Session revoke for secondary devices is fail-closed (see helper).
        deactivate_secondary_device_on_logout(&app_context, &user_id, device_id).await?;

        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Single-device logout processed"
        );
    }

    Ok(())
}

/// What `deactivate_device_unless_primary` did, so each caller can report it in its
/// own terms without re-deriving the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDeactivation {
    /// The device was active and is now unregistered; its tokens are revoked.
    Deactivated,
    /// Refused: this is the account-owning primary device. Nothing was changed.
    RefusedPrimary,
    /// Nothing to do — no such device, or it was already inactive.
    AlreadyInactive,
    /// No user row for `user_id`. Nothing was changed.
    NoSuchUser,
}

/// Deactivate `device_id` of `user_id`, **refusing the account-owning primary device**,
/// and revoke everything that device could still authenticate with.
///
/// ## Why this is one function
///
/// Deactivating a device is irreversible. `authenticate_device_core` rejects an inactive
/// device with `"Device is inactive"`, and there is no path anywhere in this workspace that
/// sets `is_active` back to TRUE — the single `UPDATE devices SET is_active` sets it FALSE.
/// The key service filters `is_active = true` on every query, so an account whose primary
/// device is deactivated also stops serving prekey bundles: no peer can start a session with
/// it, and it cannot log in to fix that. Short of an account recovery (which requires a
/// recovery key set up beforehand), that account is gone.
///
/// That is why `logout` has always refused it. `RevokeDevice` called
/// `construct_db::deactivate_device` directly and did not, so the same irreversible operation
/// had a guarded path and an unguarded one — and the unguarded one is reachable from the
/// shipped Devices screen, which offers "revoke" on every row that is not the *current*
/// device. `DeviceInfo` carries `is_current` and no `is_primary`, so from a linked desktop the
/// account-owning phone is an ordinary revocable row and the client cannot even warn.
///
/// The rule now lives with the operation rather than beside it: there is no way to reach the
/// deactivation without passing the check. Callers map the outcome to their own contract —
/// `logout` treats `RefusedPrimary` as success (the token is revoked, the registration stays),
/// `RevokeDevice` answers `FAILED_PRECONDITION`.
///
/// Redis revocation failures fail closed: reporting success would tell the caller a device can
/// no longer authenticate when it still can.
pub async fn deactivate_device_unless_primary(
    app_context: &Arc<AppContext>,
    user_id: &Uuid,
    device_id: &str,
    op: &'static str,
) -> Result<DeviceDeactivation, AppError> {
    let user = match construct_db::get_user_by_id(&app_context.db_pool, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Ok(DeviceDeactivation::NoSuchUser),
        Err(e) => {
            tracing::error!(error = %e, op, "device deactivate: failed to load user");
            return Err(AppError::internal(
                "Cannot complete request (user lookup failed)",
            ));
        }
    };

    if user.primary_device_id.as_deref() == Some(device_id) {
        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            op,
            "primary device — keeping registration (tokens only)"
        );
        return Ok(DeviceDeactivation::RefusedPrimary);
    }

    let deactivated = construct_db::deactivate_device(&app_context.db_pool, device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, op, "device deactivate: failed");
            AppError::internal("Cannot complete request (device deactivation failed)")
        })?;

    if !deactivated {
        return Ok(DeviceDeactivation::AlreadyInactive);
    }

    let mut queue = app_context.queue.lock().await;
    let access_ttl_secs =
        (app_context.config.access_token_ttl_hours * construct_config::SECONDS_PER_HOUR).max(1);
    queue
        .mark_device_revoked(device_id, access_ttl_secs)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, op, "device deactivate: failed to mark device revoked");
            AppError::internal("Cannot complete request (device revoke marker failed)")
        })?;
    // Session set is user-scoped; still clear residual keys for this user.
    if let Err(e) = queue.revoke_all_sessions(&user_id.to_string()).await {
        tracing::error!(error = %e, op, "device deactivate: failed to revoke user sessions");
        return Err(AppError::internal(
            "Cannot complete request (session revoke failed)",
        ));
    }

    tracing::info!(device_id = %device_id, op, "device unregistered");
    Ok(DeviceDeactivation::Deactivated)
}

/// Deactivate the requesting device on single-device logout, unless it is the
/// user's primary device.
async fn deactivate_secondary_device_on_logout(
    app_context: &Arc<AppContext>,
    user_id: &Uuid,
    device_id: Option<&str>,
) -> Result<(), AppError> {
    let Some(device_id) = device_id.filter(|d| !d.is_empty()) else {
        // No device_id in the token (older clients) — nothing to unregister.
        return Ok(());
    };
    // Every outcome is success for a sign-out: the token is revoked either way, and refusing
    // to unregister the primary device is the intended answer, not a failure.
    deactivate_device_unless_primary(app_context, user_id, device_id, "logout").await?;
    Ok(())
}

#[cfg(test)]
mod deactivation_guard_tests {
    use std::path::{Path, PathBuf};

    fn workspace_root() -> PathBuf {
        // crates/construct-auth-service → workspace root
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate lives two levels below the workspace root")
            .to_path_buf()
    }

    /// Every `.rs` file under the workspace's own source trees. `target/` and vendored
    /// third-party code are excluded — they are not ours and would make the scan meaningless.
    fn workspace_sources() -> Vec<(PathBuf, String)> {
        let root = workspace_root();
        let trees = [
            "crates",
            "identity-service",
            "messaging-service",
            "key-service",
            "media-service",
            "group-service",
            "signaling-service",
            "veil-service",
            "masque-service",
            "gateway",
            "shared/src",
            "shared/tests",
        ];
        let mut out = Vec::new();
        for tree in trees {
            let dir = root.join(tree);
            if !dir.exists() {
                continue;
            }
            collect(&dir, &mut out);
        }
        assert!(
            out.len() > 50,
            "scanned only {} source files — the tree layout moved and this detector is reading \
             nothing, which is worse than not having it",
            out.len()
        );
        out
    }

    fn collect(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "target" | "third_party" | ".git") {
                    continue;
                }
                collect(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }

    /// **The defect, stated as a test.**
    ///
    /// Deactivating a device is irreversible and, for the account-owning primary device,
    /// unrecoverable. `logout` refused it; `RevokeDevice` called `deactivate_device` directly and
    /// did not, so the same operation had a guarded path and an unguarded one — and the unguarded
    /// one is reachable from the shipped Devices screen.
    ///
    /// The fix is that there is now exactly one caller. This asserts that, because a second one
    /// would not fail anywhere else: it compiles, it runs, and it takes an account with it.
    #[test]
    fn deactivate_device_has_exactly_one_caller() {
        let callers: Vec<String> = workspace_sources()
            .into_iter()
            .filter(|(path, text)| {
                // The definition itself, and this file.
                !path.ends_with("construct-db/src/lib.rs")
                    && !path.ends_with("construct-auth-service/src/core.rs")
                    && text.contains("deactivate_device(")
            })
            .map(|(path, _)| path.display().to_string())
            .collect();

        assert!(
            callers.is_empty(),
            "`construct_db::deactivate_device` must be reached only through \
             `deactivate_device_unless_primary`, which holds the rule about which devices may be \
             deactivated at all. New caller(s): {callers:?}"
        );
    }

    /// The guard's premise: deactivation is one-way. If a reactivation path is ever added, the
    /// reason for refusing to deactivate the primary device weakens and the refusal should be
    /// revisited deliberately — not left standing because nobody noticed the ground moved.
    #[test]
    fn nothing_sets_a_device_active_again() {
        let offenders: Vec<String> = workspace_sources()
            .into_iter()
            .filter(|(path, text)| {
                !path.ends_with("construct-auth-service/src/core.rs")
                    && (text.contains("is_active = TRUE WHERE")
                        || text.contains("is_active = true WHERE")
                        || text.contains("SET is_active = TRUE")
                        || text.contains("SET is_active = true"))
            })
            .map(|(path, _)| path.display().to_string())
            .collect();

        assert!(
            offenders.is_empty(),
            "a device can now be reactivated ({offenders:?}). `deactivate_device_unless_primary` \
             refuses the primary device because deactivation is unrecoverable — re-read that \
             rationale before deleting this test"
        );
    }
}
