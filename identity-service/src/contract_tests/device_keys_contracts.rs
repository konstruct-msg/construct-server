//! A new device's keys are asked the same on every way in, before anything is spent or stored.
use super::*;

struct Offer {
    id: String,
    keys: proto::DevicePublicKeys,
}

type Change = fn(&mut Offer);

/// An offer wrong in one thing, with the rest made right for it: an id that follows the odd key,
/// a prekey of odd size that is signed.
fn wrong_offers() -> Vec<(&'static str, Offer)> {
    let changes: Vec<(&str, Change)> = vec![
        ("identity key short", |o| {
            o.keys.identity_public.pop();
            o.id = device_id(&o.keys.identity_public);
        }),
        ("identity key long", |o| {
            o.keys.identity_public.push(1);
            o.id = device_id(&o.keys.identity_public);
        }),
        ("prekey short", |o| resize_prekey(o, 31)),
        ("prekey long", |o| resize_prekey(o, 33)),
        ("verifying key short", |o| {
            o.keys.verifying_key.pop();
        }),
        ("prekey signature short", |o| {
            o.keys.signed_prekey_signature.pop();
        }),
        ("prekey not signed by the device", |o| {
            o.keys.signed_prekey_signature = vec![0; 64];
        }),
        ("another key's id", |o| o.id = device_id(&[3; 32])),
        ("id in capitals", |o| o.id = o.id.to_uppercase()),
    ];
    changes
        .into_iter()
        .map(|(name, change)| {
            let (_, keys) = device_keys();
            let mut offer = Offer {
                id: device_id(&keys.identity_public),
                keys,
            };
            let right = offer.id.clone();
            change(&mut offer);
            // An id of digits alone has no capitals.
            if name == "id in capitals" && offer.id == right {
                offer.id = format!("{right}A");
            }
            (name, offer)
        })
        .collect()
}

fn resize_prekey(offer: &mut Offer, size: usize) {
    let (key, keys) = device_keys();
    offer.id = device_id(&keys.identity_public);
    offer.keys = keys;
    offer.keys.signed_prekey_public = vec![41; size];
    let mut signed = b"KonstruktX3DH-v1\x00\x01".to_vec();
    signed.extend_from_slice(&offer.keys.signed_prekey_public);
    offer.keys.signed_prekey_signature = key.sign(&signed).to_bytes().to_vec();
}

async fn devices_with(f: &Fixture, offer: &Offer) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE device_id = $1 OR identity_public = $2")
        .bind(&offer.id)
        .bind(&offer.keys.identity_public)
        .fetch_one(f.service.context.db_pool.as_ref())
        .await
        .unwrap()
}

fn join_payload(offer: &Offer) -> proto::JoinRequestPayload {
    proto::JoinRequestPayload {
        pending_device_id: offer.id.clone(),
        identity_public: offer.keys.identity_public.clone(),
        verifying_key: offer.keys.verifying_key.clone(),
        signed_prekey_public: offer.keys.signed_prekey_public.clone(),
        signed_prekey_signature: offer.keys.signed_prekey_signature.clone(),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_link_refuses_wrong_keys_without_spending_its_token() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let token = f.link_token(user).await;
    let mut offers = wrong_offers();
    let (_, mut keys) = device_keys();
    keys.crypto_suite = "x".repeat(65);
    let id = device_id(&keys.identity_public);
    offers.push(("suite too long", Offer { id, keys }));
    let mut outcomes = Vec::new();
    for (name, offer) in offers {
        let code = f
            .service
            .confirm_device_link(Request::new(proto::ConfirmDeviceLinkRequest {
                link_token: token.clone(),
                device_id: offer.id.clone(),
                public_keys: Some(offer.keys.clone()),
                link_key_proof: vec![52; 32],
            }))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        outcomes.push((name, code, devices_with(&f, &offer).await));
    }
    let right = f
        .service
        .confirm_device_link(Request::new(confirm(&token)))
        .await;
    f.cleanup().await;
    for (name, code, stored) in outcomes {
        assert_eq!((code, stored), (Code::InvalidArgument, 0), "{name}");
    }
    right.expect("the token was not spent on the wrong keys");
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_join_with_wrong_keys_is_neither_stored_nor_approved() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (device, _, _) = f.device(user).await;
    let mut outcomes = Vec::new();
    for (name, offer) in wrong_offers() {
        f.keys.extend([
            format!("join_req:{}", offer.id),
            format!("join_approved:{}", offer.id),
        ]);
        let submitted = f
            .service
            .submit_join_request(Request::new(join_payload(&offer)))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        let kept = {
            let mut queue = f.service.context.queue.lock().await;
            let kept = queue.get_join_request(&offer.id).await.unwrap().is_some();
            // As a server that did not ask would have stored it.
            let data = JoinRequestData {
                pending_device_id: offer.id.clone(),
                identity_public: offer.keys.identity_public.clone(),
                verifying_key: offer.keys.verifying_key.clone(),
                signed_prekey_public: offer.keys.signed_prekey_public.clone(),
                signed_prekey_signature: offer.keys.signed_prekey_signature.clone(),
                device_name: String::new(),
                platform: String::new(),
            };
            queue
                .store_join_request(&offer.id, &rmp_serde::to_vec_named(&data).unwrap())
                .await
                .unwrap();
            kept
        };
        let approved = f
            .service
            .approve_join_request(f.request(
                user,
                Some(&device),
                proto::ApproveJoinRequestRequest {
                    pending_device_id: offer.id.clone(),
                    crypto_suite: String::new(),
                },
            ))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        outcomes.push((
            name,
            (submitted, kept, approved, devices_with(&f, &offer).await),
        ));
    }

    let (_, keys) = device_keys();
    let right = Offer {
        id: device_id(&keys.identity_public),
        keys,
    };
    f.keys.extend([
        format!("join_req:{}", right.id),
        format!("join_approved:{}", right.id),
    ]);
    let submitted = f
        .service
        .submit_join_request(Request::new(join_payload(&right)))
        .await;
    let approve = |f: &Fixture, suite: String| {
        f.request(
            user,
            Some(&device),
            proto::ApproveJoinRequestRequest {
                pending_device_id: right.id.clone(),
                crypto_suite: suite,
            },
        )
    };
    let long_suite = f
        .service
        .approve_join_request(approve(&f, "x".repeat(65)))
        .await
        .map_or_else(|e| e.code(), |_| Code::Ok);
    f.service
        .submit_join_request(Request::new(join_payload(&right)))
        .await
        .unwrap();
    let approved = f
        .service
        .approve_join_request(approve(&f, String::new()))
        .await;
    f.cleanup().await;

    for (name, outcome) in outcomes {
        assert_eq!(
            outcome,
            (Code::InvalidArgument, false, Code::InvalidArgument, 0),
            "{name}"
        );
    }
    submitted.expect("a right offer is stored");
    assert_eq!(long_suite, Code::InvalidArgument);
    approved.expect("a right offer is approved");
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_recovery_refuses_wrong_keys_before_its_proof_is_read() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (device, _, _) = f.device(user).await;
    f.keys.push(format!("revoked_device:{device}"));
    let phrase = Phrase::of(&f, user).await;
    let mut offers = wrong_offers();
    let (_, mut keys) = device_keys();
    keys.crypto_suite = "x".repeat(65);
    let id = device_id(&keys.identity_public);
    offers.push(("suite too long", Offer { id, keys }));
    let mut outcomes = Vec::new();
    for (name, offer) in offers {
        let (_, keys) = device_keys();
        let mut request = phrase.claim(user, &device_id(&keys.identity_public), keys);
        request.new_device = Some(proto::NewDeviceForRecovery {
            device_id: offer.id.clone(),
            public_keys: Some(offer.keys.clone()),
            ..Default::default()
        });
        let code = f
            .service
            .recover_account(Request::new(request))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        outcomes.push((name, code));
    }
    let alive = construct_db::device_is_active(f.service.context.db_pool.as_ref(), &device)
        .await
        .unwrap();
    f.cleanup().await;
    for (name, code) in outcomes {
        assert_eq!(code, Code::InvalidArgument, "{name}");
    }
    assert_eq!(alive, Some(true));
}
