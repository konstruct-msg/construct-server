//! A device taken out of service, through the real RPCs and the layer `main` mounts them behind.
//! Its `group_members` row stays, so nothing below the layer would stop these (264).
use tonic::Code;
use tower::Layer;

use super::grpc_support::call;
use super::test_helpers::{
    TEST_AUTH, create_test_device, create_test_group_in_db, get_test_db, get_test_redis,
    make_test_service,
};
use construct_server_shared::revocation::{RevocationCheck, RevocationLayer};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsServiceServer,
};

const SEND: &str = "/shared.proto.services.v1.MLSService/SendGroupMessage";
const FETCH: &str = "/shared.proto.services.v1.MLSService/FetchGroupMessages";

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_revoked_member_can_neither_read_nor_write_the_group() {
    let db = get_test_db().await;
    let (user, device, _) = create_test_device(&db).await;
    let group = create_test_group_in_db(&db, &device).await;
    let (token, _, _) = TEST_AUTH
        .create_token_for_device(&user, Some(&device))
        .unwrap();

    let guarded = RevocationLayer::new(
        TEST_AUTH.clone(),
        RevocationCheck::new(db.clone(), Some(get_test_redis().await)),
    )
    .layer(MlsServiceServer::new(make_test_service(db.clone()).await));

    let send = proto::SendGroupMessageRequest {
        group_id: group.to_string(),
        mls_ciphertext: vec![1],
        epoch: 0,
        client_message_id: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    };
    let fetch = proto::FetchGroupMessagesRequest {
        group_id: group.to_string(),
        limit: 1,
        ..Default::default()
    };

    assert_eq!(
        call(guarded.clone(), FETCH, Some(&token), &fetch).await.0,
        Code::Ok,
        "a member of the group reads it"
    );

    sqlx::query("UPDATE devices SET is_active = FALSE WHERE device_id = $1")
        .bind(&device)
        .execute(db.as_ref())
        .await
        .unwrap();

    assert!(
        construct_db::mls::is_group_member(db.as_ref(), group, &device)
            .await
            .unwrap(),
        "the row stays, which is why the handlers alone would let it through"
    );
    assert_eq!(
        call(guarded.clone(), FETCH, Some(&token), &fetch).await.0,
        Code::Unauthenticated
    );
    assert_eq!(
        call(guarded, SEND, Some(&token), &send).await.0,
        Code::Unauthenticated
    );
}
