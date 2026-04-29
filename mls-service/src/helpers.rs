use chrono::{DateTime, Utc};
use construct_db::mls as db_mls;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

/// Extract device_id from gRPC metadata
pub(crate) fn extract_device_id(meta: &tonic::metadata::MetadataMap) -> Result<String, Status> {
    get_metadata_str(meta, "x-device-id")
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-device-id"))
}

/// Validate Ed25519 admin proof signature with timestamp freshness check.
///
/// Verifies: Ed25519.verify(verifying_key, signature, message)
/// where message = "{operation}:{params...}:{timestamp}"
/// Timestamp must be within ±5 minutes of server time.
pub(crate) async fn verify_admin_proof(
    db: &sqlx::PgPool,
    device_id: &str,
    operation_prefix: &str,
    signature_bytes: &[u8],
    timestamp: i64,
    message: &str,
) -> Result<(), Status> {
    // 1. Timestamp freshness (±5 minutes)
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > 300 {
        return Err(Status::invalid_argument(
            "Signature timestamp expired or invalid",
        ));
    }

    // 2. Load device verifying key from DB
    let verifying_key_bytes = db_mls::get_device_verifying_key(db, device_id)
        .await
        .map_err(map_db_error)?
        .ok_or_else(|| Status::not_found("Device not found"))?;

    // 3. Parse Ed25519 public key
    let key_bytes: [u8; 32] = verifying_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("Invalid verifying_key length"))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Status::invalid_argument(format!("Invalid Ed25519 key: {}", e)))?;

    // 4. Parse signature
    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("Signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_bytes);

    // 5. Verify
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

/// Check if device is admin/creator of a group
pub(crate) async fn check_group_admin(
    db: &sqlx::PgPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<(bool, bool), Status> {
    // Returns (is_creator, is_full_admin)
    match db_mls::get_group_admin_access(db, group_id, device_id)
        .await
        .map_err(map_db_error)?
    {
        Some(access) => Ok((access.is_creator, access.is_full_admin)),
        None => Ok((false, false)),
    }
}

/// Check if device is a member of a group
pub(crate) async fn check_group_member(
    db: &sqlx::PgPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<bool, Status> {
    db_mls::is_group_member(db, group_id, device_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn check_device_belongs_to_user(
    db: &sqlx::PgPool,
    device_id: &str,
    user_id: Uuid,
) -> Result<bool, Status> {
    db_mls::device_belongs_to_user(db, device_id, user_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_dissolved_at(
    db: &sqlx::PgPool,
    group_id: Uuid,
) -> Result<Option<DateTime<Utc>>, Status> {
    db_mls::get_group_dissolved_at(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_member_count(
    db: &sqlx::PgPool,
    group_id: Uuid,
) -> Result<i64, Status> {
    db_mls::get_group_member_count(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_max_members(
    db: &sqlx::PgPool,
    group_id: Uuid,
) -> Result<i16, Status> {
    db_mls::get_group_max_members(db, group_id)
        .await
        .map_err(map_db_error)
}

pub(crate) async fn get_group_epoch(db: &sqlx::PgPool, group_id: Uuid) -> Result<i64, Status> {
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
