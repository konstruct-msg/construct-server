use chrono::Utc;
use ed25519_dalek::Signer;
use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db, get_test_redis,
    publish_test_key_package,
};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

fn make_accept_invite_request(
    group_id: uuid::Uuid,
    invite_id: uuid::Uuid,
    invitee_signing_key: &ed25519_dalek::SigningKey,
) -> proto::AcceptGroupInviteRequest {
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_GROUP_JOIN:{group_id}:{invite_id}:{timestamp}");
    let signature = invitee_signing_key.sign(message.as_bytes());
    proto::AcceptGroupInviteRequest {
        group_id: group_id.to_string(),
        invite_id: invite_id.to_string(),
        acceptance_signature: signature.to_bytes().to_vec(),
        signature_timestamp: timestamp,
        mls_commit: vec![1, 2, 3],
        new_ratchet_tree: vec![4, 5, 6],
    }
}

#[tokio::test]
async fn test_invite_to_group_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &admin_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::InviteToGroupRequest {
            group_id: group_id.to_string(),
            mls_welcome: vec![10, 20, 30],
            key_package_ref: kp_ref,
            epoch: 0,
            expires_in_seconds: 3600,
        },
    );

    let response = service
        .invite_to_group(request)
        .await
        .expect("InviteToGroup should succeed");
    let inner = response.into_inner();

    assert!(!inner.invite_id.is_empty());
    assert!(inner.expires_at > 0);
}

#[tokio::test]
async fn test_invite_to_group_non_admin() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (member_user_id, member_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add member");

    let kp_ref = publish_test_key_package(&db, member_user_id, &member_device_id).await;

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&member_user_id, &member_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::InviteToGroupRequest {
            group_id: group_id.to_string(),
            mls_welcome: vec![10, 20, 30],
            key_package_ref: kp_ref,
            epoch: 0,
            expires_in_seconds: 3600,
        },
    );

    let result = service.invite_to_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_accept_group_invite_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (invitee_user_id, invitee_device_id, invitee_signing_key) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let invite_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO group_invites
            (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
             epoch, invited_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
        "#,
    )
    .bind(invite_id)
    .bind(group_id)
    .bind(&invitee_device_id)
    .bind(vec![10u8, 20, 30])
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite");

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_GROUP_JOIN:{}:{}:{}",
        group_id, invite_id, timestamp
    );
    let signature = invitee_signing_key.sign(message.as_bytes());

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &invitee_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::AcceptGroupInviteRequest {
            group_id: group_id.to_string(),
            invite_id: invite_id.to_string(),
            acceptance_signature: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
            mls_commit: vec![1, 2, 3],
            new_ratchet_tree: vec![4, 5, 6],
        },
    );

    let response = service
        .accept_group_invite(request)
        .await
        .expect("AcceptGroupInvite should succeed");
    let inner = response.into_inner();

    assert!(inner.success);
    assert!(inner.joined_at > 0);
}

#[tokio::test]
async fn test_accept_group_invite_wrong_device() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let (_, wrong_device_id, wrong_signing_key) = create_test_device(&db).await;

    let invite_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO group_invites
            (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
             epoch, invited_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
        "#,
    )
    .bind(invite_id)
    .bind(group_id)
    .bind(&invitee_device_id)
    .bind(vec![10u8, 20, 30])
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite");

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_GROUP_JOIN:{}:{}:{}",
        group_id, invite_id, timestamp
    );
    let signature = wrong_signing_key.sign(message.as_bytes());

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &wrong_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::AcceptGroupInviteRequest {
            group_id: group_id.to_string(),
            invite_id: invite_id.to_string(),
            acceptance_signature: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
            mls_commit: vec![],
            new_ratchet_tree: vec![],
        },
    );

    let result = service.accept_group_invite(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_decline_group_invite_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let invite_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO group_invites
            (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
             epoch, invited_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
        "#,
    )
    .bind(invite_id)
    .bind(group_id)
    .bind(&invitee_device_id)
    .bind(vec![10u8, 20, 30])
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite");

    let service = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &invitee_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DeclineGroupInviteRequest {
            group_id: group_id.to_string(),
            invite_id: invite_id.to_string(),
        },
    );

    let response = service
        .decline_group_invite(request)
        .await
        .expect("DeclineGroupInvite should succeed");
    assert!(response.into_inner().success);

    let invite_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_invites WHERE invite_id = $1)")
            .bind(invite_id)
            .fetch_optional(db.as_ref())
            .await
            .expect("Failed to query")
            .flatten()
            .unwrap_or(false);

    assert!(!invite_exists);
}

#[tokio::test]
async fn test_decline_group_invite_wrong_device() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let (other_user_id, other_device_id, _) = create_test_device(&db).await;

    let invite_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO group_invites
            (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
             epoch, invited_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
        "#,
    )
    .bind(invite_id)
    .bind(group_id)
    .bind(&invitee_device_id)
    .bind(vec![10u8, 20, 30])
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite");

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&other_user_id, &other_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DeclineGroupInviteRequest {
            group_id: group_id.to_string(),
            invite_id: invite_id.to_string(),
        },
    );

    let result = service.decline_group_invite(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_get_pending_invites_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    for i in 0..3 {
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;
        let invite_id = Uuid::new_v4();
        let now = Utc::now() + chrono::Duration::seconds(i);

        sqlx::query(
            r#"
            INSERT INTO group_invites
                (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                 epoch, invited_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .bind(&invitee_device_id)
        .bind(vec![10u8, 20, 30])
        .bind(&kp_ref)
        .bind(now)
        .bind(now + chrono::Duration::hours(1))
        .execute(db.as_ref())
        .await
        .expect("Failed to create invite");
    }

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &invitee_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetPendingInvitesRequest {
            device_id: "".to_string(),
            cursor: None,
            limit: 50,
        },
    );

    let response = service
        .get_pending_invites(request)
        .await
        .expect("GetPendingInvites should succeed");
    let inner = response.into_inner();

    assert_eq!(inner.invites.len(), 3);
    assert!(inner.next_cursor.is_none());
}

#[tokio::test]
async fn test_leave_group_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (member_user_id, member_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add member");

    let service = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&member_user_id, &member_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::LeaveGroupRequest {
            group_id: group_id.to_string(),
            mls_remove_proposal: vec![1, 2, 3],
        },
    );

    let response = service
        .leave_group(request)
        .await
        .expect("LeaveGroup should succeed");
    assert!(response.into_inner().success);

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .fetch_optional(db.as_ref())
    .await
    .expect("Failed to query")
    .flatten()
    .unwrap_or(false);

    assert!(!is_member);
}

#[tokio::test]
async fn test_leave_group_creator_cannot_leave() {
    let db = get_test_db().await;
    let (admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&admin_user_id, &admin_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::LeaveGroupRequest {
            group_id: group_id.to_string(),
            mls_remove_proposal: vec![],
        },
    );

    let result = service.leave_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_remove_member_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, admin_signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (_member_user_id, member_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add member");

    let service = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&_admin_user_id, &admin_device_id);

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_REMOVE_MEMBER:{}:{}:{}",
        group_id, member_device_id, timestamp
    );
    let signature = admin_signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::RemoveMemberRequest {
            group_id: group_id.to_string(),
            target_device_id: member_device_id.clone(),
            mls_remove_proposal: vec![1, 2, 3],
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
            encrypted_reason: None,
        },
    );

    let response = service
        .remove_member(request)
        .await
        .expect("RemoveMember should succeed");
    assert!(response.into_inner().success);

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .fetch_optional(db.as_ref())
    .await
    .expect("Failed to query")
    .flatten()
    .unwrap_or(false);

    assert!(!is_member);
}

#[tokio::test]
async fn test_remove_member_cannot_remove_creator() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (other_admin_user_id, other_admin_device_id, other_admin_signing_key) =
        create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other admin as member");

    sqlx::query(
        "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, false, $3)",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other admin");

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&other_admin_user_id, &other_admin_device_id);

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_REMOVE_MEMBER:{}:{}:{}",
        group_id, admin_device_id, timestamp
    );
    let signature = other_admin_signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::RemoveMemberRequest {
            group_id: group_id.to_string(),
            target_device_id: admin_device_id.clone(),
            mls_remove_proposal: vec![],
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
            encrypted_reason: None,
        },
    );

    let result = service.remove_member(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_accept_group_invite_epoch_mismatch_rejected() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    sqlx::query("UPDATE mls_groups SET epoch = 5 WHERE group_id = $1")
        .bind(group_id)
        .execute(db.as_ref())
        .await
        .expect("Failed to advance epoch");

    let (invitee_user_id, invitee_device_id, invitee_signing_key) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let invite_id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        r#"INSERT INTO group_invites
               (invite_id, group_id, target_device_id, mls_welcome, key_package_ref, epoch, invited_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, 0, $6, $7)"#,
    )
    .bind(invite_id)
    .bind(group_id)
    .bind(&invitee_device_id)
    .bind(vec![10u8, 20, 30])
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create stale invite");

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &invitee_device_id);

    let result = service
        .accept_group_invite(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            make_accept_invite_request(group_id, invite_id, &invitee_signing_key),
        ))
        .await;

    assert!(result.is_err(), "Stale invite should be rejected");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::FailedPrecondition,
        "Expected FailedPrecondition"
    );
    assert!(
        status.message().contains("EPOCH_MISMATCH") || status.message().contains("epoch"),
        "Error should mention epoch mismatch, got: {}",
        status.message()
    );
}

#[tokio::test]
async fn test_accept_group_invite_epoch_match_succeeds() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let (invitee_user_id, invitee_device_id, invitee_signing_key) = create_test_device(&db).await;
    let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

    let invite_id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        r#"INSERT INTO group_invites
               (invite_id, group_id, target_device_id, mls_welcome, key_package_ref, epoch, invited_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, 0, $6, $7)"#,
    )
    .bind(invite_id)
    .bind(group_id)
    .bind(&invitee_device_id)
    .bind(vec![10u8, 20, 30])
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite");

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&invitee_user_id, &invitee_device_id);

    let response = service
        .accept_group_invite(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            make_accept_invite_request(group_id, invite_id, &invitee_signing_key),
        ))
        .await
        .expect("AcceptGroupInvite with matching epoch should succeed");

    let inner = response.into_inner();
    assert!(inner.success);
    assert_eq!(
        inner.new_epoch, 1,
        "Epoch should increment to 1 after join commit"
    );
}

#[tokio::test]
async fn test_get_pending_invites_cross_device_rejected_in_membership() {
    let db = get_test_db().await;
    let (attacker_user_id, attacker_device_id, _) = create_test_device(&db).await;
    let (_victim_user_id, victim_device_id, _) = create_test_device(&db).await;

    let group_id = create_test_group_in_db(&db, &attacker_device_id).await;

    let now = Utc::now();
    sqlx::query(
        r#"INSERT INTO group_invites
               (invite_id, group_id, target_device_id, mls_welcome, key_package_ref, epoch, invited_at, expires_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, 0, $5, $6)"#,
    )
    .bind(group_id)
    .bind(&victim_device_id)
    .bind(vec![0xdeu8, 0xad])
    .bind(vec![0u8; 32])
    .bind(now)
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite for victim");

    let service = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
    };
    let meta = create_metadata(&attacker_user_id, &attacker_device_id);

    let result = service
        .get_pending_invites(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetPendingInvitesRequest {
                device_id: victim_device_id.clone(),
                cursor: None,
                limit: 10,
            },
        ))
        .await;

    assert!(
        result.is_err(),
        "B3: cross-device invite fetch must be rejected"
    );
    let code = result.unwrap_err().code();
    assert!(
        code == tonic::Code::PermissionDenied || code == tonic::Code::NotFound,
        "Expected PermissionDenied or NotFound, got {code:?}"
    );
}
