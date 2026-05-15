use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

use construct_db::channel;

fn get_metadata_str<'a>(meta: &'a tonic::metadata::MetadataMap, key: &str) -> Option<&'a str> {
    meta.get(key).and_then(|v| v.to_str().ok())
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

pub(crate) async fn check_channel_admin(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<(), Status> {
    let is_admin = channel::is_channel_admin(pool, channel_id, device_id)
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
    let is_owner = channel::is_channel_owner(pool, channel_id, device_id)
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
    let is_subscriber = channel::is_channel_subscriber(pool, channel_id, device_id)
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
    let is_subscriber = channel::is_channel_subscriber(pool, channel_id, device_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !is_subscriber {
        // Also check admin (which may succeed even if not subscriber directly)
        let is_admin = channel::is_channel_admin(pool, channel_id, device_id)
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

pub(crate) async fn check_device_belongs_to_user(
    pool: &PgPool,
    device_id: &str,
    user_id: Uuid,
) -> Result<(), Status> {
    let belongs = construct_db::mls::device_belongs_to_user(pool, device_id, user_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !belongs {
        return Err(Status::permission_denied("Device does not belong to user"));
    }
    Ok(())
}
