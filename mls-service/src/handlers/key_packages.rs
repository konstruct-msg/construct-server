use construct_db::mls as db_mls;
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
        db_mls::insert_group_key_package(
            svc.db.as_ref(),
            db_mls::NewGroupKeyPackage {
                user_id,
                device_id: &device_id,
                key_package: kp.as_slice(),
                key_package_ref: kp_ref.as_slice(),
                published_at: now,
                expires_at,
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    }

    let count = db_mls::count_key_packages_for_device(svc.db.as_ref(), &device_id)
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

    let row = db_mls::consume_key_package_for_user(
        svc.db.as_ref(),
        user_id,
        req.preferred_device_id.as_deref(),
    )
    .await
    .map_err(|e| Status::internal(e.to_string()))?;

    match row {
        None => Err(Status::not_found(
            "no KeyPackage available for this user; they must publish more",
        )),
        Some(consumed) => {
            info!(
                target_user_id = %user_id,
                device_id = %consumed.device_id,
                "KeyPackage consumed"
            );
            Ok(Response::new(proto::ConsumeKeyPackageResponse {
                key_package: consumed.key_package,
                device_id: consumed.device_id,
                key_package_ref: consumed.key_package_ref,
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

    let stats = db_mls::get_key_package_count(svc.db.as_ref(), user_id, req.device_id.as_deref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(proto::GetKeyPackageCountResponse {
        count: stats.count as u32,
        recommended_minimum: 20,
        last_published_at: stats.last_published_at.map(|t| t.timestamp()).unwrap_or(0),
        cannot_be_invited: stats.count == 0,
    }))
}
