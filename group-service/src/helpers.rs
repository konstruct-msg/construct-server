use chrono::{DateTime, Utc};
use construct_db::channel as db_channel;
use construct_db::mls as db_mls;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sqlx::PgPool;
use tonic::Status;
use tracing::warn;
use uuid::Uuid;

fn get_metadata_str<'a>(meta: &'a tonic::metadata::MetadataMap, key: &str) -> Option<&'a str> {
    meta.get(key).and_then(|v| v.to_str().ok())
}

fn map_db_error(error: impl std::fmt::Display) -> Status {
    Status::internal(format!("DB error: {}", error))
}

pub(crate) fn extract_user_id(meta: &tonic::metadata::MetadataMap) -> Result<Uuid, Status> {
    get_metadata_str(meta, "x-user-id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))
}

pub(crate) fn extract_device_id(meta: &tonic::metadata::MetadataMap) -> Result<String, Status> {
    get_metadata_str(meta, "x-device-id")
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-device-id"))
}

pub(crate) async fn verify_admin_proof(
    db: &PgPool,
    device_id: &str,
    operation_prefix: &str,
    signature_bytes: &[u8],
    timestamp: i64,
    message: &str,
) -> Result<(), Status> {
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > 300 {
        return Err(Status::invalid_argument(
            "Signature timestamp expired or invalid",
        ));
    }

    let verifying_key_bytes = db_mls::get_device_verifying_key(db, device_id)
        .await
        .map_err(map_db_error)?
        .ok_or_else(|| Status::not_found("Device not found"))?;

    let key_bytes: [u8; 32] = verifying_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("Invalid verifying_key length"))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Status::invalid_argument(format!("Invalid Ed25519 key: {}", e)))?;

    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("Signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| {
            warn!(
                device_id = %device_id,
                operation = %operation_prefix,
                error = %e,
                "Admin proof signature verification failed"
            );
            Status::permission_denied("Invalid admin proof signature")
        })
}

pub(crate) async fn check_group_admin(
    db: &PgPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<(bool, bool), Status> {
    match db_mls::get_group_admin_access(db, group_id, device_id)
        .await
        .map_err(map_db_error)?
    {
        Some(access) => Ok((access.is_creator, access.is_full_admin)),
        None => Ok((false, false)),
    }
}

pub(crate) async fn check_group_member(
    db: &PgPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<bool, Status> {
    db_mls::is_group_member(db, group_id, device_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn check_device_belongs_to_user(
    db: &PgPool,
    device_id: &str,
    user_id: Uuid,
) -> Result<bool, Status> {
    db_mls::device_belongs_to_user(db, device_id, user_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_dissolved_at(
    db: &PgPool,
    group_id: Uuid,
) -> Result<Option<DateTime<Utc>>, Status> {
    db_mls::get_group_dissolved_at(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_member_count(db: &PgPool, group_id: Uuid) -> Result<i64, Status> {
    db_mls::get_group_member_count(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_max_members(db: &PgPool, group_id: Uuid) -> Result<i16, Status> {
    db_mls::get_group_max_members(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_epoch(db: &PgPool, group_id: Uuid) -> Result<i64, Status> {
    db_mls::get_group_epoch(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ── Channel helpers ──

pub(crate) async fn check_channel_admin(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<(), Status> {
    let is_admin = db_channel::is_channel_admin(pool, channel_id, device_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !is_admin {
        return Err(Status::permission_denied("Not a channel admin"));
    }
    Ok(())
}

pub(crate) async fn check_channel_owner(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<(), Status> {
    let is_owner = db_channel::is_channel_owner(pool, channel_id, device_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !is_owner {
        return Err(Status::permission_denied("Not the channel owner"));
    }
    Ok(())
}

pub(crate) async fn check_channel_subscriber(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<(), Status> {
    let is_subscriber = db_channel::is_channel_subscriber(pool, channel_id, device_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !is_subscriber {
        return Err(Status::permission_denied("Not a channel subscriber"));
    }
    Ok(())
}

pub(crate) async fn check_channel_subscriber_or_admin(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<(), Status> {
    let is_subscriber = db_channel::is_channel_subscriber(pool, channel_id, device_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !is_subscriber {
        let is_admin = db_channel::is_channel_admin(pool, channel_id, device_id)
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?;
        if !is_admin {
            return Err(Status::permission_denied(
                "Not a channel subscriber or admin",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn check_warmup_rate_limit(
    redis: &mut redis::aio::ConnectionManager,
    pool: &PgPool,
    user_id: Uuid,
    action: &str,
    warmup_max: u32,
    warmup_window_hours: i64,
    established_max: u32,
    established_window_hours: i64,
) -> Result<(), Status> {
    let in_warmup = construct_rate_limit::is_user_in_warmup_cached(redis, pool, user_id)
        .await
        .unwrap_or(true);

    let (max_events, window_hours) = if in_warmup {
        (warmup_max, warmup_window_hours)
    } else {
        (established_max, established_window_hours)
    };

    let key = format!("rl:channel:{}:{}", action, user_id);
    let allowed = construct_rate_limit::sliding_window_check_and_record(
        redis,
        &key,
        max_events,
        window_hours * 3600,
    )
    .await
    .map_err(|e| Status::internal(format!("Rate limit error: {e}")))?;

    if !allowed {
        crate::metrics::inc_channel_rate_limit_violations();
        return Err(Status::resource_exhausted(format!(
            "RATE_LIMIT: max {} {}/{} hours (account warming: {})",
            max_events, action, window_hours, in_warmup
        )));
    }

    Ok(())
}
