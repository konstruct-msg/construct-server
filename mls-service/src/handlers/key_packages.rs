use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::helpers::{extract_user_id, sha256_bytes};
use crate::service::MlsServiceImpl;

pub(crate) async fn publish_key_package(
    svc: &MlsServiceImpl,
    request: Request<proto::PublishKeyPackageRequest>,
) -> Result<Response<proto::PublishKeyPackageResponse>, Status> {
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let device_id = req.device_id;
    if device_id.is_empty() {
        return Err(Status::invalid_argument("device_id is required"));
    }
    if req.key_packages.is_empty() {
        return Err(Status::invalid_argument(
            "at least one key_package required",
        ));
    }

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::days(30);

    for kp in &req.key_packages {
        let kp_ref = sha256_bytes(kp);
        sqlx::query(
            r#"
            INSERT INTO group_key_packages
                (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (key_package_ref) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(&device_id)
        .bind(kp.as_slice())
        .bind(kp_ref.as_slice())
        .bind(now)
        .bind(expires_at)
        .execute(svc.db.as_ref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    }

    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM group_key_packages
        WHERE device_id = $1
          AND expires_at > NOW()
        "#,
    )
    .bind(&device_id)
    .fetch_one(svc.db.as_ref())
    .await
    .map_err(|e| Status::internal(e.to_string()))?;

    info!(
        device_id = %device_id,
        user_id = %user_id,
        published = req.key_packages.len(),
        total = count,
        "KeyPackages published"
    );

    Ok(Response::new(proto::PublishKeyPackageResponse {
        count: count as u32,
        published_at: now.timestamp(),
    }))
}

pub(crate) async fn consume_key_package(
    svc: &MlsServiceImpl,
    request: Request<proto::ConsumeKeyPackageRequest>,
) -> Result<Response<proto::ConsumeKeyPackageResponse>, Status> {
    let req = request.into_inner();

    let user_id =
        Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("invalid user_id"))?;

    let row: Option<(Vec<u8>, String, Vec<u8>)> =
        if let Some(ref preferred) = req.preferred_device_id {
            sqlx::query_as(
                r#"
            DELETE FROM group_key_packages
            WHERE id = (
                SELECT id FROM group_key_packages
                WHERE user_id = $1
                  AND device_id = $2
                  AND expires_at > NOW()
                ORDER BY published_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_package, device_id, key_package_ref
            "#,
            )
            .bind(user_id)
            .bind(preferred)
            .fetch_optional(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        } else {
            sqlx::query_as(
                r#"
            DELETE FROM group_key_packages
            WHERE id = (
                SELECT id FROM group_key_packages
                WHERE user_id = $1
                  AND expires_at > NOW()
                ORDER BY published_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_package, device_id, key_package_ref
            "#,
            )
            .bind(user_id)
            .fetch_optional(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        };

    match row {
        None => Err(Status::not_found(
            "no KeyPackage available for this user; they must publish more",
        )),
        Some((key_package, device_id, key_package_ref)) => {
            info!(
                target_user_id = %user_id,
                device_id = %device_id,
                "KeyPackage consumed"
            );
            Ok(Response::new(proto::ConsumeKeyPackageResponse {
                key_package,
                device_id,
                key_package_ref,
            }))
        }
    }
}

pub(crate) async fn get_key_package_count(
    svc: &MlsServiceImpl,
    request: Request<proto::GetKeyPackageCountRequest>,
) -> Result<Response<proto::GetKeyPackageCountResponse>, Status> {
    let req = request.into_inner();

    let user_id =
        Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("invalid user_id"))?;

    let (count, last_published_at): (i64, Option<chrono::DateTime<chrono::Utc>>) =
        if let Some(ref device_id) = req.device_id {
            sqlx::query_as(
                r#"
                SELECT COUNT(*), MAX(published_at)
                FROM group_key_packages
                WHERE user_id = $1
                  AND device_id = $2
                  AND expires_at > NOW()
                "#,
            )
            .bind(user_id)
            .bind(device_id)
            .fetch_one(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        } else {
            sqlx::query_as(
                r#"
                SELECT COUNT(*), MAX(published_at)
                FROM group_key_packages
                WHERE user_id = $1
                  AND expires_at > NOW()
                "#,
            )
            .bind(user_id)
            .fetch_one(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        };

    Ok(Response::new(proto::GetKeyPackageCountResponse {
        count: count as u32,
        recommended_minimum: 20,
        last_published_at: last_published_at.map(|t| t.timestamp()).unwrap_or(0),
        cannot_be_invited: count == 0,
    }))
}
