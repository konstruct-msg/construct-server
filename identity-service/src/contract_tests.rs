//! Exercise the real RPCs/core with PostgreSQL and Redis, never a copied dispatcher.
//! Each fixture owns random accounts and Redis keys; no global environment edits or FLUSHDB.
use super::*;
use construct_server_shared::revocation::{RevocationCheck, RevocationLayer};
use construct_server_shared::shared::proto::services::v1::{
    device_link_service_server::DeviceLinkService, device_service_server::DeviceService,
    user_service_server::UserServiceServer,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use prost::Message;
use tonic::Code;
use tower::Layer;
use uuid::Uuid;

#[path = "../../shared/test_support/grpc.rs"]
mod grpc_support;

struct Fixture {
    service: IdentityGrpcService,
    users: Vec<Uuid>,
    keys: Vec<String>,
}

impl Fixture {
    async fn new() -> Self {
        let config = Arc::new(test_config::config());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(&config.database_url)
            .await
            .expect("Postgres required");
        let queue = MessageQueue::new(&config).await.expect("Redis required");
        let auth_manager =
            Arc::new(construct_server_shared::auth::AuthManager::new(&config).unwrap());
        let service = IdentityGrpcService {
            context: Arc::new(IdentityServiceContext {
                db_pool: Arc::new(pool),
                queue: Arc::new(Mutex::new(queue)),
                auth_manager,
                config,
                server_signer: None,
                token_enc_pub: Some([31; 32]),
                token_issuer_pub: Some(construct_crypto::privacy_pass::issuer_public_key(
                    &[23; 32],
                )),
                token_issuer_key_version: 7,
                notification_client: None,
            }),
            veil_bridge_cert: None,
            token_issuer_key: Some([23; 32]),
            token_issuance_max_per_hour: 24,
            token_issuance_young_max_per_hour: 3,
            token_issuance_maturity_hours: 24,
            cert_signing_key: Some(SigningKey::from_bytes(&[29; 32])),
            cert_hybrid_signer: None,
        };
        Self {
            service,
            users: Vec::new(),
            keys: Vec::new(),
        }
    }

    async fn user(&mut self) -> Uuid {
        let id = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
            .fetch_one(self.service.context.db_pool.as_ref())
            .await
            .unwrap();
        self.users.push(id);
        // A run crossing the hour boundary still cleans up both counters.
        let hour = chrono::Utc::now().timestamp() / 3600;
        for h in [hour, hour + 1] {
            self.keys.push(format!("rate:pp_tokens:{id}:{h}"));
        }
        id
    }

    fn request<T>(&self, user: Uuid, device: Option<&str>, body: T) -> Request<T> {
        let (token, _, _) = self
            .service
            .context
            .auth_manager
            .create_token_for_device(&user, device)
            .unwrap();
        let mut req = Request::new(body);
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        if let Some(id) = device {
            req.metadata_mut()
                .insert("x-device-id", id.parse().unwrap());
        }
        req
    }

    async fn device(&self, user: Uuid) -> (String, SigningKey, proto::DevicePublicKeys) {
        let id = Uuid::new_v4().simple().to_string();
        let (key, public) = device_keys();
        construct_db::create_device(
            self.service.context.db_pool.as_ref(),
            construct_db::CreateDeviceData {
                device_id: id.clone(),
                server_hostname: "test.local".into(),
                verifying_key: public.verifying_key.clone(),
                identity_public: public.identity_public.clone(),
                signed_prekey_public: public.signed_prekey_public.clone(),
                signed_prekey_signature: public.signed_prekey_signature.clone(),
                crypto_suites: "[\"Curve25519+Ed25519\"]".into(),
                supports_pq_ratchet: false,
            },
            Some(user),
        )
        .await
        .unwrap();
        (id, key, public)
    }

    async fn link_token(&mut self, user: Uuid) -> String {
        let token = Uuid::new_v4().to_string();
        self.service
            .context
            .queue
            .lock()
            .await
            .store_device_link_token(&token, &user.to_string())
            .await
            .unwrap();
        self.keys.extend([
            format!("device_link:{token}"),
            format!("device_link_result:{token}"),
        ]);
        token
    }

    async fn join(&mut self) -> String {
        let id = Uuid::new_v4().simple().to_string();
        let (_, keys) = device_keys();
        let data = JoinRequestData {
            pending_device_id: id.clone(),
            identity_public: keys.identity_public,
            verifying_key: keys.verifying_key,
            signed_prekey_public: keys.signed_prekey_public,
            signed_prekey_signature: keys.signed_prekey_signature,
            device_name: String::new(),
            platform: String::new(),
        };
        self.service
            .context
            .queue
            .lock()
            .await
            .store_join_request(&id, &rmp_serde::to_vec_named(&data).unwrap())
            .await
            .unwrap();
        self.keys
            .extend([format!("join_req:{id}"), format!("join_approved:{id}")]);
        id
    }

    async fn cleanup(mut self) {
        for user in &self.users {
            construct_db::delete_user_account(
                self.service.context.db_pool.as_ref(),
                user,
                &self.service.context.config.security.contact_hmac_secret,
            )
            .await
            .unwrap();
        }
        let mut queue = self.service.context.queue.lock().await;
        for user in &self.users {
            queue
                .revoke_all_user_tokens(&user.to_string())
                .await
                .unwrap();
        }
        for key in &self.keys {
            queue.delete(key).await.unwrap();
        }
        drop(queue);
        self.users.clear();
        self.keys.clear();
    }
}

// Mutation runs intentionally panic at assertions. Their random accounts must still be removed.
// Use fresh connections on a separate runtime: the panicking test's runtime is about to stop.
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.users.is_empty() && self.keys.is_empty() {
            return;
        }
        let users = std::mem::take(&mut self.users);
        let keys = std::mem::take(&mut self.keys);
        let config = self.service.context.config.clone();
        let result = std::thread::spawn(move || -> anyhow::Result<()> {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let pool = DbPool::connect(&config.database_url).await?;
                    let mut queue = MessageQueue::new(&config).await?;
                    for user in users {
                        queue.revoke_all_user_tokens(&user.to_string()).await?;
                        construct_db::delete_user_account(
                            &pool,
                            &user,
                            &config.security.contact_hmac_secret,
                        )
                        .await?;
                    }
                    for key in keys {
                        queue.delete(&key).await?;
                    }
                    pool.close().await;
                    Ok(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("identity fixture cleanup failed: {result:?}");
        }
    }
}

fn device_keys() -> (SigningKey, proto::DevicePublicKeys) {
    let seed: [u8; 32] = [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()]
        .concat()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&seed);
    let spk = vec![41; 32];
    let mut body = b"KonstruktX3DH-v1\x00\x01".to_vec();
    body.extend_from_slice(&spk);
    let public = proto::DevicePublicKeys {
        verifying_key: key.verifying_key().to_bytes().to_vec(),
        identity_public: seed.to_vec(),
        signed_prekey_public: spk,
        signed_prekey_signature: key.sign(&body).to_bytes().to_vec(),
        crypto_suite: "Curve25519+Ed25519".into(),
        ..Default::default()
    };
    (key, public)
}

fn points(n: usize) -> Vec<Vec<u8>> {
    (1..=n)
        .map(|i| {
            (Scalar::from(i as u64) * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes()
                .to_vec()
        })
        .collect()
}

async fn issue(
    f: &Fixture,
    user: Uuid,
    points: Vec<Vec<u8>>,
) -> Result<proto::IssueTokensResponse, Status> {
    f.service
        .issue_tokens(f.request(
            user,
            None,
            proto::IssueTokensRequest {
                blinded_points: points,
            },
        ))
        .await
        .map(Response::into_inner)
}

fn check_proof(response: &proto::IssueTokensResponse, requested: &[Vec<u8>]) {
    assert!(!response.evaluated_points.is_empty());
    assert_eq!(response.issuer_key_version, 7);
    let key = [23; 32];
    let commitment = construct_crypto::privacy_pass::issuer_public_key(&key);
    assert_eq!(response.server_pubkey, commitment);
    let blinded: Vec<[u8; 32]> = requested
        .iter()
        .take(response.evaluated_points.len())
        .map(|p| p.as_slice().try_into().unwrap())
        .collect();
    let evaluated: Vec<[u8; 32]> = response
        .evaluated_points
        .iter()
        .map(|p| p.as_slice().try_into().unwrap())
        .collect();
    for (b, z) in blinded.iter().zip(&evaluated) {
        let point = curve25519_dalek::ristretto::CompressedRistretto(*b)
            .decompress()
            .unwrap();
        assert_eq!(
            *z,
            (Scalar::from_bytes_mod_order(key) * point)
                .compress()
                .to_bytes()
        );
    }
    let proof = response
        .dleq_proof
        .as_slice()
        .try_into()
        .expect("64-byte DLEQ proof required");
    assert!(construct_crypto::privacy_pass::verify_dleq_proof(
        &commitment,
        &blinded,
        &evaluated,
        proof
    ));
    let mut altered = evaluated.clone();
    altered[0] = [0; 32];
    assert!(!construct_crypto::privacy_pass::verify_dleq_proof(
        &commitment,
        &blinded,
        &altered,
        proof
    ));
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn issuance_rejects_bad_points_without_spending_the_hour() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let mut malformed = vec![
        vec![],
        points(21),
        vec![vec![1; 31]],
        vec![vec![1; 33]],
        vec![vec![255; 32]],
        vec![vec![0; 32]],
    ];
    let mut mixed = points(1);
    mixed.push(vec![0; 32]);
    malformed.push(mixed);
    for batch in malformed {
        assert_eq!(
            issue(&f, user, batch).await.unwrap_err().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            f.service
                .context
                .queue
                .lock()
                .await
                .token_issuance_count(&user.to_string())
                .await
                .unwrap(),
            0
        );
    }
    check_proof(&issue(&f, user, points(1)).await.unwrap(), &points(1));
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .token_issuance_count(&user.to_string())
            .await
            .unwrap(),
        1
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn issuance_partial_batch_proves_exactly_the_granted_prefix_and_exhausts_cleanly() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    // Unknown account age fails to the young tier (3); 2 + 1, then no grant.
    check_proof(&issue(&f, user, points(2)).await.unwrap(), &points(2));
    let response = issue(&f, user, points(20)).await.unwrap();
    assert_eq!(response.evaluated_points.len(), 1);
    check_proof(&response, &points(20));
    assert_eq!(
        issue(&f, user, points(1)).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .token_issuance_count(&user.to_string())
            .await
            .unwrap(),
        3
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn issuance_accepts_twenty_for_mature_account_and_never_borrows_from_next_hour() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    f.device(user).await;
    sqlx::query(
        "UPDATE devices SET registered_at = NOW() - INTERVAL '25 hours' WHERE user_id = $1",
    )
    .bind(user)
    .execute(f.service.context.db_pool.as_ref())
    .await
    .unwrap();
    let response = issue(&f, user, points(20)).await.unwrap();
    assert_eq!(response.evaluated_points.len(), 20);
    check_proof(&response, &points(20));
    let remainder = issue(&f, user, points(20)).await.unwrap();
    assert_eq!(remainder.evaluated_points.len(), 4);
    check_proof(&remainder, &points(20));
    assert_eq!(
        issue(&f, user, points(1)).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .token_issuance_count(&user.to_string())
            .await
            .unwrap(),
        24
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn issuance_requires_key_and_authentication() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    assert_eq!(
        f.service
            .issue_tokens(Request::new(proto::IssueTokensRequest {
                blinded_points: points(1)
            }))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    f.service.token_issuer_key = None;
    assert_eq!(
        issue(&f, user, points(1)).await.unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .token_issuance_count(&user.to_string())
            .await
            .unwrap(),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn sender_certificate_binds_active_device_account_key_domain_and_lifetime() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (device, _, keys) = f.device(user).await;
    let start = chrono::Utc::now().timestamp();
    let response = f
        .service
        .get_sender_certificate(f.request(
            user,
            Some(&device),
            proto::GetSenderCertificateRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    let cert = construct_server_shared::shared::proto::core::v1::SenderCertificate::decode(
        response.certificate.as_slice(),
    )
    .unwrap();
    assert_eq!(cert.sender_user_id, user.to_string());
    assert_eq!(cert.sender_device_id, device);
    assert_eq!(cert.sender_identity_key, keys.identity_public);
    assert_eq!(cert.sender_domain, "test.local");
    assert!(cert.issued_at >= start && cert.issued_at <= chrono::Utc::now().timestamp());
    assert_eq!(
        cert.expires_at - cert.issued_at,
        construct_crypto::server_trust::SENDER_CERT_MAX_LIFETIME_SECS
    );
    assert_eq!(response.expires_at, cert.expires_at);
    assert_eq!(response.token_encryption_key, vec![31; 32]);
    let body = build_sender_cert_sign_payload(
        &cert.sender_user_id,
        &cert.sender_domain,
        &cert.sender_identity_key,
        &cert.sender_device_id,
        cert.issued_at,
        cert.expires_at,
    );
    let sig = Ed25519Signature::from_slice(&cert.server_signature).unwrap();
    let verifier = f.service.cert_signing_key.as_ref().unwrap().verifying_key();
    verifier.verify(&body, &sig).unwrap();
    let substituted = build_sender_cert_sign_payload(
        &cert.sender_user_id,
        &cert.sender_domain,
        &cert.sender_identity_key,
        "00000000000000000000000000000000",
        cert.issued_at,
        cert.expires_at,
    );
    assert!(verifier.verify(&substituted, &sig).is_err());
    sqlx::query("UPDATE devices SET is_active = false WHERE device_id = $1")
        .bind(&device)
        .execute(f.service.context.db_pool.as_ref())
        .await
        .unwrap();
    assert_eq!(
        f.service
            .get_sender_certificate(f.request(
                user,
                Some(&device),
                proto::GetSenderCertificateRequest {}
            ))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn sender_certificate_refuses_missing_key_header_foreign_account_and_sibling_spoof() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let other = f.user().await;
    let (device, _, _) = f.device(user).await;
    let (sibling, _, _) = f.device(user).await;
    assert_eq!(
        f.service
            .get_sender_certificate(f.request(user, None, proto::GetSenderCertificateRequest {}))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        f.service
            .get_sender_certificate(f.request(other, None, proto::GetSenderCertificateRequest {}))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    let mut foreign = f.request(other, None, proto::GetSenderCertificateRequest {});
    foreign
        .metadata_mut()
        .insert("x-device-id", device.parse().unwrap());
    assert_eq!(
        f.service
            .get_sender_certificate(foreign)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let mut spoof = f.request(user, Some(&device), proto::GetSenderCertificateRequest {});
    spoof
        .metadata_mut()
        .insert("x-device-id", sibling.parse().unwrap());
    assert_eq!(
        f.service
            .get_sender_certificate(spoof)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    f.service.cert_signing_key = None;
    assert_eq!(
        f.service
            .get_sender_certificate(f.request(
                user,
                Some(&device),
                proto::GetSenderCertificateRequest {}
            ))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    f.cleanup().await;
}

fn confirm(token: &str, device: &str) -> proto::ConfirmDeviceLinkRequest {
    proto::ConfirmDeviceLinkRequest {
        link_token: token.into(),
        device_id: device.into(),
        public_keys: Some(device_keys().1),
        link_key_proof: vec![52; 32],
    }
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn confirm_link_is_single_use_returns_bound_tokens_and_preserves_key_proof() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let token = f.link_token(user).await;
    let device = Uuid::new_v4().simple().to_string();
    let req = confirm(&token, &device);
    let tokens = f
        .service
        .confirm_device_link(Request::new(req.clone()))
        .await
        .unwrap()
        .into_inner()
        .tokens
        .unwrap();
    let claims = f
        .service
        .context
        .auth_manager
        .verify_token(&tokens.access_token)
        .unwrap();
    assert_eq!(claims.sub, user.to_string());
    assert_eq!(claims.device_id.as_deref(), Some(device.as_str()));
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .get_device_link_result(&token)
            .await
            .unwrap(),
        Some((user.to_string(), device.clone(), vec![52; 32]))
    );
    assert_eq!(
        f.service
            .confirm_device_link(Request::new(req))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let stored = construct_db::get_device_by_id(f.service.context.db_pool.as_ref(), &device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.user_id, Some(user));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn confirm_link_rejects_expired_tokens_and_invalid_key_proofs() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let token = f.link_token(user).await;
    let device = Uuid::new_v4().simple().to_string();
    let mut req = confirm(&token, &device);
    req.link_key_proof = vec![1; 31];
    assert_eq!(
        f.service
            .confirm_device_link(Request::new(req))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .peek_device_link_token(&token)
            .await
            .unwrap(),
        Some(user.to_string())
    );
    // An expired Redis entry is absent; no wall-clock sleep or production TTL changes.
    f.service
        .context
        .queue
        .lock()
        .await
        .delete(&format!("device_link:{token}"))
        .await
        .unwrap();
    assert_eq!(
        f.service
            .confirm_device_link(Request::new(confirm(&token, &device)))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert!(
        !construct_db::device_exists(f.service.context.db_pool.as_ref(), &device)
            .await
            .unwrap()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn approval_refuses_header_spoof_without_consuming_join_and_accepts_once() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let stranger = f.user().await;
    let (device, _, _) = f.device(user).await;
    let pending = f.join().await;
    let body = proto::ApproveJoinRequestRequest {
        pending_device_id: pending.clone(),
        crypto_suite: String::new(),
    };
    let mut spoof = f.request(user, Some(&device), body.clone());
    spoof
        .metadata_mut()
        .insert("x-user-id", stranger.to_string().parse().unwrap());
    assert_eq!(
        f.service
            .approve_join_request(spoof)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        f.service
            .context
            .queue
            .lock()
            .await
            .get_join_request(&pending)
            .await
            .unwrap()
            .is_some()
    );
    let tokens = f
        .service
        .approve_join_request(f.request(user, Some(&device), body.clone()))
        .await
        .unwrap()
        .into_inner()
        .tokens
        .unwrap();
    assert_eq!(tokens.user_id, user.to_string());
    let claims = f
        .service
        .context
        .auth_manager
        .verify_token(&tokens.access_token)
        .unwrap();
    assert_eq!(claims.device_id.as_deref(), Some(pending.as_str()));
    assert_eq!(
        f.service
            .approve_join_request(f.request(user, Some(&device), body))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let linked = construct_db::get_device_by_id(f.service.context.db_pool.as_ref(), &pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(linked.user_id, Some(user));
    f.cleanup().await;
}

async fn signed_invite(
    f: &Fixture,
    user: Uuid,
    device: &str,
    key: &SigningKey,
) -> crypto_agility::InviteToken {
    let addr = key.verifying_key().to_bytes().to_vec();
    sqlx::query("UPDATE users SET recovery_public_key = $1 WHERE id = $2")
        .bind(&addr)
        .bind(user)
        .execute(f.service.context.db_pool.as_ref())
        .await
        .unwrap();
    let mut invite = crypto_agility::InviteToken {
        v: 5,
        jti: Uuid::new_v4(),
        uuid: user,
        device_id: device.into(),
        server: "test.local".into(),
        ts: chrono::Utc::now().timestamp(),
        sig: String::new(),
        username: None,
        ttl: 300,
        addr,
    };
    resign(&mut invite, key);
    invite
}

fn resign(invite: &mut crypto_agility::InviteToken, key: &SigningKey) {
    invite.sig = b64::STANDARD.encode(
        key.sign(invite.canonical_string().unwrap().as_bytes())
            .to_bytes(),
    );
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn invite_signature_checks_encoding_key_signature_and_account_ownership() {
    use invite_core::{InviteSignatureError as E, verify_invite_signature as verify};
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let stranger = f.user().await;
    let (device, key, _) = f.device(user).await;
    let invite = signed_invite(&f, user, &device, &key).await;
    let pool = f.service.context.db_pool.as_ref();
    verify(pool, &invite).await.unwrap();
    let mut bad = invite.clone();
    bad.sig = "!".into();
    assert!(matches!(
        verify(pool, &bad).await,
        Err(E::InvalidSignature(_))
    ));
    bad.sig = b64::STANDARD.encode([0; 63]);
    assert!(matches!(
        verify(pool, &bad).await,
        Err(E::InvalidSignature(_))
    ));
    bad = invite.clone();
    bad.ttl += 1;
    assert!(matches!(
        verify(pool, &bad).await,
        Err(E::VerificationFailed)
    ));
    bad = invite.clone();
    bad.uuid = stranger;
    resign(&mut bad, &key);
    assert!(
        matches!(verify(pool, &bad).await, Err(E::DeviceNotFound)),
        "a device signed for another account"
    );
    sqlx::query("UPDATE devices SET verifying_key = $1 WHERE device_id = $2")
        .bind(vec![0u8; 31])
        .bind(&device)
        .execute(pool)
        .await
        .unwrap();
    assert!(matches!(
        verify(pool, &invite).await,
        Err(E::InvalidVerifyingKey(_))
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn invite_accept_burns_once_links_both_accounts_and_revoke_prevents_acceptance() {
    use invite_core::{AcceptInviteInput, RevokeInviteInput, accept_invite, revoke_invite};
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let accepter = f.user().await;
    let (device, key, _) = f.device(user).await;
    let invite = signed_invite(&f, user, &device, &key).await;
    let ctx = &f.service.context;
    let out = accept_invite(
        ctx,
        AcceptInviteInput {
            accepter_user_id: accepter,
            invite: invite.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(out.user_id, user.to_string());
    assert_eq!(out.device_id.as_deref(), Some(device.as_str()));
    assert_eq!(out.server, "test.local");
    let secret = &ctx.config.security.contact_hmac_secret;
    let a = construct_db::contact_link_hmac(secret, &accepter);
    let b = construct_db::contact_link_hmac(secret, &user);
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contact_links WHERE (user_hmac = $1 AND peer_hmac = $2) OR (user_hmac = $2 AND peer_hmac = $1)")
        .bind(a).bind(b).fetch_one(ctx.db_pool.as_ref()).await.unwrap();
    assert_eq!(links, 2, "mutual contact link missing");
    let err = accept_invite(
        ctx,
        AcceptInviteInput {
            accepter_user_id: accepter,
            invite: invite.clone(),
        },
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(
        err.downcast_ref::<construct_error::AppError>(),
        Some(construct_error::AppError::InviteAlreadyUsed)
    ));
    let mut revoked = invite;
    revoked.jti = Uuid::new_v4();
    resign(&mut revoked, &key);
    let revoke = || RevokeInviteInput {
        user_id: user,
        jti: revoked.jti.to_string(),
    };
    assert!(revoke_invite(ctx, revoke()).await.unwrap().success);
    assert!(!revoke_invite(ctx, revoke()).await.unwrap().success);
    let retention: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM expires_at - NOW())::bigint FROM used_invites WHERE jti = $1",
    )
    .bind(revoked.jti)
    .fetch_one(ctx.db_pool.as_ref())
    .await
    .unwrap();
    assert!(
        (crypto_agility::INVITE_BURN_RETENTION_SECONDS - 10
            ..=crypto_agility::INVITE_BURN_RETENTION_SECONDS)
            .contains(&retention)
    );
    let err = accept_invite(
        ctx,
        AcceptInviteInput {
            accepter_user_id: accepter,
            invite: revoked,
        },
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(
        err.downcast_ref::<construct_error::AppError>(),
        Some(construct_error::AppError::InviteAlreadyUsed)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn link_and_join_tokens_have_one_consumer_across_server_instances() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    for join in [false, true] {
        let id = if join {
            f.join().await
        } else {
            f.link_token(user).await
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = tokio::task::JoinSet::new();
        // Each queue has its own Redis connection, as separate service replicas do.
        let mut queues = Vec::new();
        for _ in 0..16 {
            queues.push(MessageQueue::new(&f.service.context.config).await.unwrap());
        }
        for mut queue in queues {
            let barrier = barrier.clone();
            let id = id.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                if join {
                    queue.consume_join_request(&id).await.unwrap().is_some()
                } else {
                    queue
                        .consume_device_link_token(&id)
                        .await
                        .unwrap()
                        .is_some()
                }
            });
        }
        let mut winners = 0;
        while let Some(result) = tasks.join_next().await {
            winners += u32::from(result.unwrap());
        }
        assert_eq!(
            winners, 1,
            "one-time token had {winners} consumers, join={join}"
        );
    }
    f.cleanup().await;
}

#[test]
fn issuance_age_boundary_is_inclusive_and_future_age_is_young() {
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    assert_eq!(
        effective_issuance_cap(Some(now - chrono::Duration::hours(24)), now, 24, 3, 24),
        (24, true)
    );
    assert_eq!(
        effective_issuance_cap(
            Some(now - chrono::Duration::hours(24) + chrono::Duration::seconds(1)),
            now,
            24,
            3,
            24
        ),
        (3, false)
    );
    assert_eq!(
        effective_issuance_cap(Some(now + chrono::Duration::seconds(1)), now, 24, 3, 24),
        (3, false)
    );
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn issuance_rejects_header_spoof_without_charging_either_account() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let other = f.user().await;
    let mut req = f.request(
        user,
        None,
        proto::IssueTokensRequest {
            blinded_points: points(1),
        },
    );
    req.metadata_mut()
        .insert("x-user-id", other.to_string().parse().unwrap());
    assert_eq!(
        f.service.issue_tokens(req).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    for id in [user, other] {
        assert_eq!(
            f.service
                .context
                .queue
                .lock()
                .await
                .token_issuance_count(&id.to_string())
                .await
                .unwrap(),
            0
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn issuance_reservation_is_atomic_and_refusal_leaves_the_counter_unchanged() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let mut q = f.service.context.queue.lock().await;
    assert_eq!(
        q.try_reserve_token_issuance(&user.to_string(), 2, 3)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        q.try_reserve_token_issuance(&user.to_string(), 2, 3)
            .await
            .unwrap(),
        0
    );
    assert_eq!(q.token_issuance_count(&user.to_string()).await.unwrap(), 2);
    assert_eq!(
        q.try_reserve_token_issuance(&user.to_string(), 0, 3)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        q.try_reserve_token_issuance(&user.to_string(), 1, 3)
            .await
            .unwrap(),
        1
    );
    drop(q);
    let contender = f.user().await.to_string();
    let mut tasks = tokio::task::JoinSet::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut queues = Vec::new();
    for _ in 0..16 {
        queues.push(MessageQueue::new(&f.service.context.config).await.unwrap());
    }
    for mut queue in queues {
        let id = contender.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            queue.try_reserve_token_issuance(&id, 1, 3).await.unwrap()
        });
    }
    let mut granted = 0;
    while let Some(result) = tasks.join_next().await {
        granted += result.unwrap();
    }
    assert_eq!(granted, 3);
    assert_eq!(
        f.service
            .context
            .queue
            .lock()
            .await
            .token_issuance_count(&contender)
            .await
            .unwrap(),
        3
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn invite_rejections_do_not_burn_jti_and_inactive_signers_are_refused() {
    use invite_core::{AcceptInviteInput, accept_invite};
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let accepter = f.user().await;
    let (device, key, _) = f.device(user).await;
    let invite = signed_invite(&f, user, &device, &key).await;
    let mut wrong_addr = invite.clone();
    wrong_addr.addr = vec![61; 32];
    resign(&mut wrong_addr, &key);
    let mut expired = invite.clone();
    expired.ts -= 301;
    resign(&mut expired, &key);
    let mut bad_sig = invite.clone();
    bad_sig.sig = b64::STANDARD.encode([0; 64]);
    for bad in [wrong_addr, expired, bad_sig] {
        assert!(
            accept_invite(
                &f.service.context,
                AcceptInviteInput {
                    accepter_user_id: accepter,
                    invite: bad
                }
            )
            .await
            .is_err()
        );
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM used_invites WHERE jti = $1)")
                .bind(invite.jti)
                .fetch_one(f.service.context.db_pool.as_ref())
                .await
                .unwrap();
        assert!(!exists, "rejected invite burned jti");
    }
    sqlx::query("UPDATE devices SET is_active = false WHERE device_id = $1")
        .bind(&device)
        .execute(f.service.context.db_pool.as_ref())
        .await
        .unwrap();
    assert!(matches!(
        invite_core::verify_invite_signature(f.service.context.db_pool.as_ref(), &invite).await,
        Err(invite_core::InviteSignatureError::DeviceNotFound)
    ));
    f.cleanup().await;
}

#[test]
fn invite_signer_must_be_active_and_belong_to_claimed_account() {
    let owner = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    assert!(invite_core::invite_signer_matches(Some(owner), true, owner));
    assert!(!invite_core::invite_signer_matches(
        Some(owner),
        false,
        owner
    ));
    assert!(!invite_core::invite_signer_matches(
        Some(other),
        true,
        owner
    ));
    assert!(!invite_core::invite_signer_matches(None, true, owner));
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn link_result_is_visible_only_to_the_issuing_account() {
    use proto::get_device_link_result_response::Status as LinkStatus;
    let mut f = Fixture::new().await;
    let owner = f.user().await;
    let stranger = f.user().await;
    let token = f.link_token(owner).await;
    let body = || proto::GetDeviceLinkResultRequest {
        link_token: token.clone(),
    };
    for (caller, expected) in [
        (owner, LinkStatus::Pending),
        (stranger, LinkStatus::Expired),
    ] {
        let result = f
            .service
            .get_device_link_result(f.request(caller, None, body()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.status, expected as i32);
        assert!(result.device_id.is_empty());
        assert!(result.link_key_proof.is_empty());
    }
    let device = Uuid::new_v4().simple().to_string();
    f.service
        .confirm_device_link(Request::new(confirm(&token, &device)))
        .await
        .unwrap();
    let owned = f
        .service
        .get_device_link_result(f.request(owner, None, body()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(owned.status, LinkStatus::Confirmed as i32);
    assert_eq!(owned.device_id, device);
    assert_eq!(owned.link_key_proof, vec![52; 32]);
    let foreign = f
        .service
        .get_device_link_result(f.request(stranger, None, body()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(foreign.status, LinkStatus::Expired as i32);
    assert!(foreign.device_id.is_empty());
    assert!(foreign.link_key_proof.is_empty());
    f.cleanup().await;
}

// ── 264: what a token is worth after its device is gone ──────────────────────

/// A real recovery: the phrase's hybrid key set on the account, a claim for a new device.
async fn recover(f: &Fixture, user: Uuid) -> Result<proto::RecoverAccountResponse, Status> {
    use construct_crypto::pqc::hybrid::{hybrid_sign, hybrid_signature_keypair_from_seeds};
    use construct_crypto::server_trust::recovery as claim_bytes;
    let (private, public) = hybrid_signature_keypair_from_seeds(&rand::random(), &rand::random());
    let now = chrono::Utc::now().timestamp();
    let setup = claim_bytes::setup_signable(&user.to_string(), now, &public).unwrap();
    recovery::set_recovery_key(
        f.service.context.db_pool.as_ref(),
        user,
        &public,
        &hybrid_sign(&private, &setup).unwrap(),
        now,
        None,
    )
    .await
    .unwrap();

    let device_id = Uuid::new_v4().simple().to_string();
    let (_, keys) = device_keys();
    let claim = claim_bytes::claim_signable(
        &public,
        now,
        &device_id,
        &keys.verifying_key,
        &keys.identity_public,
    )
    .unwrap();
    f.service
        .recover_account(Request::new(proto::RecoverAccountRequest {
            identifier: user.to_string(),
            recovery_public_key: public,
            recovery_signature: hybrid_sign(&private, &claim).unwrap(),
            timestamp: now,
            new_device: Some(proto::NewDeviceForRecovery {
                device_id,
                public_keys: Some(keys),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .map(Response::into_inner)
}

/// The layer as `main` builds it, on the same stores.
async fn guard(f: &Fixture) -> RevocationLayer {
    let client = redis::Client::open(f.service.context.config.redis_url.as_str()).unwrap();
    RevocationLayer::new(
        f.service.context.auth_manager.clone(),
        RevocationCheck::new(
            f.service.context.db_pool.clone(),
            Some(construct_redis::manager_for(client).await.unwrap()),
        ),
    )
    .with_open_methods(RPCS_THAT_DO_NOT_READ_THE_BEARER)
}

const USER: &str = "/shared.proto.services.v1.UserService";
const DEVICE: &str = "/shared.proto.services.v1.DeviceService";
const AUTH: &str = "/shared.proto.services.v1.AuthService";

/// An account with a primary device, and a second device already revoked by it. Returns the
/// tokens the devices held before that, and the primary's id.
async fn account_with_a_revoked_device(f: &mut Fixture) -> (Uuid, String, String, String, String) {
    let user = f.user().await;
    let (primary, _, _) = f.device(user).await;
    let (stolen, _, _) = f.device(user).await;
    construct_db::set_primary_device(f.service.context.db_pool.as_ref(), &user, &primary)
        .await
        .unwrap();
    let mint = |device: &str| {
        f.service
            .context
            .auth_manager
            .create_token_for_device(&user, Some(device))
            .unwrap()
            .0
    };
    let primary_token = mint(&primary);
    let stolen_token = mint(&stolen);
    f.service
        .revoke_device(f.request(
            user,
            Some(&primary),
            proto::RevokeDeviceRequest {
                device_id: stolen.clone(),
            },
        ))
        .await
        .unwrap();
    f.keys.push(format!("revoked_device:{stolen}"));
    (user, primary, primary_token, stolen, stolen_token)
}

/// The defect 264 opened on: this deleted the account (reproduced on main 2026-11-06).
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_revoked_devices_token_can_no_longer_act_on_the_account() {
    let mut f = Fixture::new().await;
    let (user, _, primary_token, stolen, stolen_token) =
        account_with_a_revoked_device(&mut f).await;
    let guard = guard(&f).await;
    let users = guard.layer(UserServiceServer::new(f.service.clone()));
    let devices = guard.layer(proto::device_service_server::DeviceServiceServer::new(
        f.service.clone(),
    ));

    let delete = proto::DeleteAccountRequest {
        confirmation: "DELETE".into(),
        reason: None,
    };
    let (code, headers) = grpc_support::call(
        users.clone(),
        &format!("{USER}/DeleteAccount"),
        Some(&stolen_token),
        &delete,
    )
    .await;
    assert_eq!(code, Code::Unauthenticated);
    assert!(
        headers.get("construct-device-refusal").is_none(),
        "only identity's refresh and authenticate may tell a client to erase itself"
    );
    assert!(
        construct_db::get_user_by_id(f.service.context.db_pool.as_ref(), &user)
            .await
            .unwrap()
            .is_some(),
        "the account is still there"
    );

    let export = proto::ExportUserDataRequest::default();
    let path = format!("{USER}/ExportUserData");
    assert_eq!(
        grpc_support::call(users.clone(), &path, Some(&stolen_token), &export)
            .await
            .0,
        Code::Unauthenticated,
    );
    assert_eq!(
        grpc_support::call(
            devices,
            &format!("{DEVICE}/RevokeDevice"),
            Some(&stolen_token),
            &proto::RevokeDeviceRequest { device_id: stolen },
        )
        .await
        .0,
        Code::Unauthenticated,
        "a revoked device must not revoke its siblings either"
    );
    assert_eq!(
        grpc_support::call(users, &path, Some(&primary_token), &export)
            .await
            .0,
        Code::Ok,
        "the device that stayed goes on working"
    );
    f.cleanup().await;
}

/// The sign-out-wipes-the-device signal: a dead token must still reach the handler that gives it.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_removed_device_still_learns_it_was_removed() {
    let mut f = Fixture::new().await;
    let (user, _, _, stolen, stolen_token) = account_with_a_revoked_device(&mut f).await;
    let refresh = f
        .service
        .context
        .auth_manager
        .create_refresh_token_for_device(&user, Some(&stolen))
        .unwrap()
        .0;
    let auth = guard(&f)
        .await
        .layer(proto::auth_service_server::AuthServiceServer::new(
            f.service.clone(),
        ));
    let (code, headers) = grpc_support::call(
        auth,
        &format!("{AUTH}/RefreshToken"),
        Some(&stolen_token),
        &proto::RefreshTokenRequest {
            refresh_token: refresh,
            device_id: stolen,
        },
    )
    .await;
    assert_eq!(code, Code::Unauthenticated);
    assert_eq!(
        headers
            .get("construct-device-refusal")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "the client erases itself on this number, and nothing else"
    );
    f.cleanup().await;
}

/// `Logout` takes its token in the body, past the layer.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_revoked_device_cannot_sign_the_account_out() {
    let mut f = Fixture::new().await;
    let (user, _, _, _, stolen_token) = account_with_a_revoked_device(&mut f).await;
    let (_, jti, _) = f
        .service
        .context
        .auth_manager
        .create_refresh_token_for_device(&user, None)
        .unwrap();
    {
        let mut queue = f.service.context.queue.lock().await;
        queue
            .store_refresh_token(&jti, &user.to_string(), 60)
            .await
            .unwrap();
    }
    f.keys.push(format!("refresh_token:{jti}"));

    let answer = f
        .service
        .logout(Request::new(proto::LogoutRequest {
            access_token: stolen_token.clone(),
            all_devices: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(answer.success, "it asks to be signed out, and it is");
    let survives = redis::cmd("EXISTS")
        .arg(format!("refresh_token:{jti}"))
        .query_async::<bool>(
            &mut construct_redis::manager_for(
                redis::Client::open(f.service.context.config.redis_url.as_str()).unwrap(),
            )
            .await
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(survives, "the account's other sessions were left alone");

    let verified = f
        .service
        .verify_token(Request::new(proto::VerifyTokenRequest {
            access_token: stolen_token,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!verified.valid, "VerifyToken tells the same story");
    f.cleanup().await;
}

/// A retry reaches the marker even though the row was deactivated by the failed first attempt.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn revoking_an_inactive_device_again_restores_a_lost_marker() {
    let mut f = Fixture::new().await;
    let (user, primary, _, stolen, _) = account_with_a_revoked_device(&mut f).await;
    let mut queue = f.service.context.queue.lock().await;
    queue
        .delete(&format!("revoked_device:{stolen}"))
        .await
        .unwrap();
    assert!(!queue.is_device_revoked(&stolen).await.unwrap());
    drop(queue);

    f.service
        .revoke_device(f.request(
            user,
            Some(&primary),
            proto::RevokeDeviceRequest {
                device_id: stolen.clone(),
            },
        ))
        .await
        .unwrap();
    let marked = f
        .service
        .context
        .queue
        .lock()
        .await
        .is_device_revoked(&stolen)
        .await
        .unwrap();
    assert!(marked);
    f.cleanup().await;
}

/// The stolen-phone case: after recovery the old device is out everywhere, the new one is in.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn recovery_takes_every_old_device_out_of_messaging_and_the_rest() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (old, _, _) = f.device(user).await;
    f.keys.push(format!("revoked_device:{old}"));
    let old_token = f
        .service
        .context
        .auth_manager
        .create_token_for_device(&user, Some(&old))
        .unwrap()
        .0;

    let recovered = recover(&f, user).await.expect("recovery succeeds");
    assert_eq!(recovered.devices_revoked, 1);

    let marked = f
        .service
        .context
        .queue
        .lock()
        .await
        .is_device_revoked(&old)
        .await
        .unwrap();
    assert!(
        marked,
        "messaging reads this marker: without it the old device's token still reads the mailbox"
    );

    let users = guard(&f)
        .await
        .layer(UserServiceServer::new(f.service.clone()));
    let export = proto::ExportUserDataRequest::default();
    let path = format!("{USER}/ExportUserData");
    assert_eq!(
        grpc_support::call(users.clone(), &path, Some(&old_token), &export)
            .await
            .0,
        Code::Unauthenticated
    );
    let new_token = recovered.tokens.expect("tokens").access_token;
    assert_eq!(
        grpc_support::call(users, &path, Some(&new_token), &export)
            .await
            .0,
        Code::Ok
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn deleting_an_account_marks_its_devices_revoked() {
    let mut f = Fixture::new().await;
    let user = f.user().await;
    let (device, _, _) = f.device(user).await;
    f.keys.push(format!("revoked_device:{device}"));
    f.service
        .delete_account(f.request(
            user,
            Some(&device),
            proto::DeleteAccountRequest {
                confirmation: "DELETE".into(),
                reason: None,
            },
        ))
        .await
        .unwrap();
    let marked = f
        .service
        .context
        .queue
        .lock()
        .await
        .is_device_revoked(&device)
        .await
        .unwrap();
    assert!(marked);
    f.cleanup().await;
}

/// The list is the handlers that read no bearer, exactly. One too many leaves an RPC open to a dead
/// token; one too few closes the door a removed device learns through.
#[test]
fn the_rpcs_open_to_a_dead_token_are_the_ones_that_never_read_it() {
    let source = include_str!("main.rs");
    let reads_the_bearer = |body: &str| {
        [
            "request_token(",
            "extract_user_id_from_metadata(",
            "verify_access_token(",
            ".metadata()",
        ]
        .iter()
        .any(|call| body.contains(call))
    };
    let mut open = std::collections::BTreeSet::new();
    let mut in_rpc_impl = false;
    let mut current: Option<(String, String)> = None;
    let mut flush = |current: &mut Option<(String, String)>| {
        if let Some((name, body)) = current.take()
            && !reads_the_bearer(&body)
        {
            let camel: String = name
                .split('_')
                .map(|part| {
                    let mut chars = part.chars();
                    chars
                        .next()
                        .unwrap()
                        .to_uppercase()
                        .chain(chars)
                        .collect::<String>()
                })
                .collect();
            open.insert(camel);
        }
    };
    for line in source.lines() {
        if line.starts_with("impl ") && line.ends_with("for IdentityGrpcService {") {
            in_rpc_impl = true;
        } else if line == "}" {
            flush(&mut current);
            in_rpc_impl = false;
        } else if in_rpc_impl {
            if let Some(rest) = line.strip_prefix("    async fn ") {
                flush(&mut current);
                let name = rest.split('(').next().unwrap().to_string();
                current = Some((name, String::new()));
            } else if let Some((_, body)) = current.as_mut() {
                body.push_str(line);
            }
        }
    }
    assert!(open.len() > 5, "the walk found no handlers: {open:?}");
    open.insert("GetServerTrust".to_string()); // its service lives in server_trust_rpc.rs
    let listed: std::collections::BTreeSet<String> = RPCS_THAT_DO_NOT_READ_THE_BEARER
        .iter()
        .map(|m| m.to_string())
        .collect();
    assert_eq!(open, listed);
}
