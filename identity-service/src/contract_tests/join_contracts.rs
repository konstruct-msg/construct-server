//! A join lets in the device that asked, with the keys it asked with.
use super::device_auth::redis_of;
use super::*;
use proto::auth_service_server::AuthService;

fn payload(id: &str, keys: &proto::DevicePublicKeys) -> proto::JoinRequestPayload {
    proto::JoinRequestPayload {
        pending_device_id: id.to_string(),
        identity_public: keys.identity_public.clone(),
        verifying_key: keys.verifying_key.clone(),
        signed_prekey_public: keys.signed_prekey_public.clone(),
        signed_prekey_signature: keys.signed_prekey_signature.clone(),
        ..Default::default()
    }
}

impl Fixture {
    async fn offered(&mut self) -> (String, SigningKey, proto::DevicePublicKeys) {
        let (key, keys) = device_keys();
        let id = device_id(&keys.identity_public);
        self.keys
            .extend([format!("join_req:{id}"), format!("join_approved:{id}")]);
        self.service
            .submit_join_request(Request::new(payload(&id, &keys)))
            .await
            .unwrap();
        (id, key, keys)
    }

    async fn approve(
        &self,
        user: Uuid,
        device: &str,
        pending: &str,
    ) -> proto::ApproveJoinRequestResponse {
        self.service
            .approve_join_request(self.request(
                user,
                Some(device),
                proto::ApproveJoinRequestRequest {
                    pending_device_id: pending.to_string(),
                    crypto_suite: String::new(),
                },
            ))
            .await
            .unwrap()
            .into_inner()
    }
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn an_offer_is_not_replaced_by_one_with_other_keys() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (device, _, _) = f.device(user).await;
    let (pending, _, keys) = f.offered().await;
    let submit = |keys: &proto::DevicePublicKeys, name: &str| {
        let mut p = payload(&pending, keys);
        p.device_name = name.to_string();
        f.service.submit_join_request(Request::new(p))
    };

    // What the QR shows: the id and the identity key. The rest is the stranger's own.
    let (_, mut theirs) = device_keys();
    theirs.identity_public = keys.identity_public.clone();
    let code = |r: Result<_, Status>| r.map_or_else(|e| e.code(), |_: Response<_>| Code::Ok);
    let replaced = code(submit(&theirs, "").await);
    let renamed = code(submit(&keys, "another name").await);
    let repeated = code(submit(&keys, "").await);

    let mut redis = redis_of(&f).await;
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("join_req:{pending}"))
        .query_async(&mut redis)
        .await
        .unwrap();
    f.approve(user, &device, &pending).await;
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT verifying_key FROM devices WHERE device_id = $1")
            .bind(&pending)
            .fetch_one(f.service.context.db_pool.as_ref())
            .await
            .unwrap();
    f.cleanup().await;
    assert_eq!(
        (replaced, renamed, repeated),
        (Code::AlreadyExists, Code::AlreadyExists, Code::Ok)
    );
    assert!((500..=600).contains(&ttl), "ten minutes to approve: {ttl}");
    assert!(stored == keys.verifying_key, "a stranger's key was let in");
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn an_approver_is_given_no_tokens_and_the_joined_device_signs_in_with_its_key() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (device, _, _) = f.device(user).await;
    let (pending, key, _) = f.offered().await;
    let t = chrono::Utc::now().timestamp();
    let early = f.sign_in(&pending, &key, t).await;
    let answer = f.approve(user, &device, &pending).await;
    let (other, _) = device_keys();
    let foreign = f.sign_in(&pending, &other, t).await;
    let tokens = f.sign_in(&pending, &key, t).await;
    let claims = tokens
        .as_ref()
        .ok()
        .map(|t| f.service.context.auth_manager.verify_token(&t.access_token));
    f.cleanup().await;
    assert!(early.is_err(), "not a device of any account yet");
    assert!(answer.tokens.is_none());
    assert_eq!(foreign.unwrap_err().code(), Code::Unauthenticated);
    let claims = claims.expect("the joined device signs in").unwrap();
    assert_eq!(claims.sub, user.to_string());
    assert_eq!(claims.device_id.as_deref(), Some(pending.as_str()));
}
