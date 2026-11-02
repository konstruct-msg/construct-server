//! Task 237: run the receiver's real verification/claim/dispatch path. Only HTTPS key
//! discovery is supplied in-memory; these tests never contact an external federation node.
use super::*;
use construct_auth::AuthManager;
use construct_config::StealthTokenPolicy;
use construct_db::DbPool;
use construct_queue::MessageQueue;
use construct_server_shared::shared::proto::core::v1::SealedInner;
use prost::Message;
use redis::AsyncCommands;
use tokio::sync::Mutex;

const ORIGIN: &str = "origin.example";
const DESTINATION: &str = "destination.example";

type Response = Result<(StatusCode, Json<FederationResponse>), FedHttpErr>;

#[derive(Clone)]
struct TestRequest {
    envelope: FederatedEnvelope,
    payload: String,
}

struct Harness {
    ctx: Arc<MessagingServiceContext>,
    signer: ServerSigner,
    recipient: String,
    sender: String,
}

impl Harness {
    async fn new() -> Self {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:password@127.0.0.1:5432/construct_test".into()
        });
        let pool = DbPool::connect(&db_url).await.expect("requires Postgres");
        sqlx::migrate!("../shared/migrations")
            .run(&pool)
            .await
            .expect("migrations");
        let kp = ed25519_compact::KeyPair::generate();
        let mut config = crate::sealed_matrix_tests::make_config(
            &redis_url,
            &db_url,
            &kp.sk.to_pem(),
            &kp.pk.to_pem(),
            StealthTokenPolicy::Off,
        );
        config.federation.enabled = true;
        config.federation.instance_domain = DESTINATION.into();
        config.federation.max_requests_per_origin_per_hour = 0;
        let queue = MessageQueue::new(&config).await.expect("requires Redis");
        assert!(
            queue.mailbox_user_write_enabled(),
            "test checks the legacy user mailbox"
        );
        let auth_manager = Arc::new(AuthManager::new(&config).unwrap());
        let ctx = Arc::new(MessagingServiceContext {
            db_pool: Arc::new(pool),
            queue: Arc::new(Mutex::new(queue)),
            auth_manager,
            notification_context: None,
            sentinel: None,
            config: Arc::new(config),
            server_signer: None,
            server_instance_id: uuid::Uuid::new_v4().to_string(),
            redis_conn: construct_redis::connect_manager(&redis_url).await.unwrap(),
            token_issuer_key: None,
            token_enc_static_secret: None,
        });
        Self {
            ctx,
            signer: ServerSigner::from_seed_base64(
                &base64::engine::general_purpose::STANDARD.encode([37; 32]),
                ORIGIN.into(),
            )
            .unwrap(),
            recipient: uuid::Uuid::new_v4().to_string(),
            sender: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn envelope(&self, sealed: bool) -> TestRequest {
        let payload = if sealed {
            base64::engine::general_purpose::STANDARD.encode(
                SealedInner {
                    recipient_user_id: self.recipient.clone(),
                    delivery_tag: uuid::Uuid::new_v4().as_bytes().to_vec(),
                    sender_cert_ciphertext: vec![1; 48],
                    encrypted_payload: vec![0, 1, 255],
                    ..Default::default()
                }
                .encode_to_vec(),
            )
        } else {
            base64::engine::general_purpose::STANDARD.encode([0, 1, 255])
        };
        TestRequest {
            envelope: FederatedEnvelope {
                message_id: uuid::Uuid::new_v4().to_string(),
                from: if sealed {
                    String::new()
                } else {
                    self.sender.clone()
                },
                to: if sealed {
                    String::new()
                } else {
                    self.recipient.clone()
                },
                origin_server: ORIGIN.into(),
                destination_server: DESTINATION.into(),
                timestamp: Utc::now().timestamp() as u64,
                payload_hash: FederatedEnvelope::hash_payload(&payload),
            },
            payload,
        }
    }

    // Run the production receiver with a deterministic origin-key lookup.
    async fn receive(
        &self,
        sealed: bool,
        request: TestRequest,
        signature: Option<String>,
    ) -> Response {
        let TestRequest {
            envelope: e,
            payload,
        } = request;
        let pk = self.signer.public_key_base64();
        let lookup = async move |origin: String| match origin.as_str() {
            ORIGIN | "alias.example" => Ok(pk),
            _ => Err(SigningError::RemoteKeyFetch("origin unavailable".into())),
        };
        if sealed {
            receive_sealed(
                self.ctx.clone(),
                InboundSealedRequest {
                    message_id: e.message_id,
                    sealed_inner: payload,
                    origin_server: e.origin_server,
                    timestamp: e.timestamp,
                    payload_hash: e.payload_hash,
                    server_signature: signature,
                },
                lookup,
            )
            .await
        } else {
            receive_message(
                self.ctx.clone(),
                InboundMessageRequest {
                    message_id: e.message_id,
                    from: e.from,
                    to: e.to,
                    ciphertext: payload,
                    origin_server: e.origin_server,
                    timestamp: e.timestamp,
                    payload_hash: e.payload_hash,
                    server_signature: signature,
                },
                lookup,
            )
            .await
        }
    }

    fn signed(&self, request: &TestRequest) -> String {
        self.signer.sign_message(&request.envelope)
    }

    fn claim_key(request: &TestRequest) -> String {
        federation_message_key(
            &request.envelope.origin_server,
            &request.envelope.message_id,
        )
    }

    async fn claimed(&self, e: &TestRequest) -> bool {
        self.ctx
            .redis_conn
            .clone()
            .exists(Self::claim_key(e))
            .await
            .unwrap()
    }

    async fn mailbox(&self) -> Vec<construct_message::MessageEnvelope> {
        let mut conn = self.ctx.redis_conn.clone();
        let entries: Vec<(String, std::collections::HashMap<String, Vec<u8>>)> =
            redis::cmd("XRANGE")
                .arg(format!("delivery:offline:{}", self.recipient))
                .arg("-")
                .arg("+")
                .query_async(&mut conn)
                .await
                .unwrap();
        entries
            .into_iter()
            .map(|(_, fields)| rmp_serde::from_slice(&fields["payload"]).unwrap())
            .collect()
    }

    async fn cleanup(&self, envelopes: &[TestRequest]) {
        let mut keys = vec![format!("delivery:offline:{}", self.recipient)];
        for e in envelopes {
            keys.push(Self::claim_key(e));
        }
        let _: usize = self.ctx.redis_conn.clone().del(keys).await.unwrap();
    }
}

fn status(result: Response, expected: StatusCode) {
    let (actual, body) = result.expect_err("request must be rejected");
    assert_eq!(actual, expected, "{}", body.0);
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn unsigned_and_tampered_requests_cannot_claim_or_deliver() {
    let h = Harness::new().await;
    for sealed in [false, true] {
        let e = h.envelope(sealed);
        status(
            h.receive(sealed, e.clone(), None).await,
            StatusCode::UNAUTHORIZED,
        );
        assert!(!h.claimed(&e).await);
        let signature = h.signed(&e);
        // The envelope destination is reconstructed from local config, never taken from
        // attacker-controlled JSON. A signature for C must be rejected at B.
        let mut wrong_destination = e.clone();
        wrong_destination.envelope.destination_server = "other.example".into();
        status(
            h.receive(sealed, e.clone(), Some(h.signed(&wrong_destination)))
                .await,
            StatusCode::UNAUTHORIZED,
        );
        for field in 0..6 {
            if sealed && (field == 1 || field == 2) {
                continue;
            }
            let mut changed = e.clone();
            match field {
                0 => changed.envelope.message_id.push('x'),
                1 => changed.envelope.from.push('x'),
                2 => changed.envelope.to.push('x'),
                3 => changed.envelope.timestamp += 1,
                4 => {
                    changed.payload.push('x');
                    changed.envelope.payload_hash =
                        FederatedEnvelope::hash_payload(&changed.payload);
                }
                5 => changed.envelope.origin_server = "alias.example".into(),
                _ => unreachable!(),
            }
            status(
                h.receive(sealed, changed.clone(), Some(signature.clone()))
                    .await,
                StatusCode::UNAUTHORIZED,
            );
            assert!(!h.claimed(&changed).await);
        }
        assert!(!h.claimed(&e).await);
        assert!(h.mailbox().await.is_empty());
        // Invalid signature must also fail when the ID is already claimed.
        let _: () = h
            .ctx
            .redis_conn
            .clone()
            .set_ex(Harness::claim_key(&e), "1", 60)
            .await
            .unwrap();
        status(
            h.receive(sealed, e.clone(), Some("invalid".into())).await,
            StatusCode::UNAUTHORIZED,
        );
        h.cleanup(&[e]).await;
    }
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn accepted_requests_write_once_and_claim_for_seven_days() {
    let h = Harness::new().await;
    for sealed in [false, true] {
        let e = h.envelope(sealed);
        let signature = h.signed(&e);
        let (_, Json(response)) = h
            .receive(sealed, e.clone(), Some(signature.clone()))
            .await
            .unwrap();
        assert_eq!(response.status, "accepted");
        let messages = h.mailbox().await;
        assert_eq!(messages.len(), 1);
        if sealed {
            assert!(messages[0].is_sealed_sender);
            assert!(messages[0].encrypted_payload.is_empty());
            assert_eq!(
                messages[0].sealed_inner.as_ref().unwrap(),
                &base64::engine::general_purpose::STANDARD
                    .decode(&e.payload)
                    .unwrap()
            );
        } else {
            assert_eq!(messages[0].encrypted_payload, [0, 1, 255]);
            assert_eq!(messages[0].sender_id, h.sender);
            assert_eq!(messages[0].recipient_id, h.recipient);
            assert_eq!(messages[0].message_id, e.envelope.message_id);
        }
        let ttl: i64 = h
            .ctx
            .redis_conn
            .clone()
            .ttl(Harness::claim_key(&e))
            .await
            .unwrap();
        assert!((604_795..=604_800).contains(&ttl), "claim TTL was {ttl}");
        let (_, Json(response)) = h.receive(sealed, e.clone(), Some(signature)).await.unwrap();
        assert_eq!(response.status, "duplicate");
        assert_eq!(h.mailbox().await.len(), 1);
        h.cleanup(&[e]).await;
    }
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn failed_dispatch_releases_claim_and_retry_reaches_mailbox() {
    let h = Harness::new().await;
    for sealed in [false, true] {
        let e = h.envelope(sealed);
        let key = format!("delivery:offline:{}", h.recipient);
        let _: () = h
            .ctx
            .redis_conn
            .clone()
            .set(&key, "WRONGTYPE")
            .await
            .unwrap();
        let signature = h.signed(&e);
        status(
            h.receive(sealed, e.clone(), Some(signature.clone())).await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert!(!h.claimed(&e).await, "failed write poisoned the retry");
        let _: usize = h.ctx.redis_conn.clone().del(&key).await.unwrap();
        let (_, Json(response)) = h.receive(sealed, e.clone(), Some(signature)).await.unwrap();
        assert_eq!(response.status, "accepted");
        assert_eq!(h.mailbox().await.len(), 1);
        h.cleanup(&[e]).await;
    }
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn invalid_sealed_base64_never_poison_claim() {
    let h = Harness::new().await;
    let mut e = h.envelope(true);
    e.payload = "not base64!".into();
    e.envelope.payload_hash = FederatedEnvelope::hash_payload(&e.payload);
    let signature = h.signed(&e);
    for _ in 0..2 {
        status(
            h.receive(true, e.clone(), Some(signature.clone())).await,
            StatusCode::BAD_REQUEST,
        );
        assert!(
            !h.claimed(&e).await,
            "invalid base64 left a claim without any message"
        );
    }
    assert!(h.mailbox().await.is_empty());
}

#[test]
fn timestamp_near_signed_integer_limit_is_rejected_without_panicking() {
    let timestamp = Utc::now().timestamp() as u64 + i64::MAX as u64;
    assert_eq!(
        validate_federation_timestamp(timestamp).unwrap_err().0,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn timestamp_skew_boundaries_and_full_unsigned_range() {
    let now = 1_793_491_200;
    for timestamp in [now, now - 300, now + 300] {
        assert!(validate_federation_timestamp_at(timestamp, now).is_ok());
    }
    for timestamp in [now - 301, now + 301, 0, i64::MAX as u64, u64::MAX] {
        assert_eq!(
            validate_federation_timestamp_at(timestamp, now)
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[test]
fn replay_keys_bind_origin_and_message_id_without_delimiter_aliases() {
    let key = federation_message_key("origin.example", "message");
    assert_eq!(key, federation_message_key("origin.example", "message"));
    assert_ne!(key, federation_message_key("other.example", "message"));
    assert_ne!(key, federation_message_key("origin.example", "other"));
    assert_ne!(
        federation_message_key("origin.example:443", "message"),
        federation_message_key("origin.example", "443:message")
    );
    assert_ne!(key, "fed:msg:origin.example:message");
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn disabled_http_handlers_return_404_before_any_key_discovery() {
    let mut h = Harness::new().await;
    Arc::get_mut(&mut Arc::get_mut(&mut h.ctx).unwrap().config)
        .unwrap()
        .federation
        .enabled = false;
    let req = h.envelope(false);
    status(
        handle_inbound_message(
            State(h.ctx.clone()),
            Json(InboundMessageRequest {
                message_id: req.envelope.message_id,
                from: req.envelope.from,
                to: req.envelope.to,
                ciphertext: req.payload,
                origin_server: "127.0.0.1".into(),
                timestamp: 0,
                payload_hash: String::new(),
                server_signature: None,
            }),
        )
        .await,
        StatusCode::NOT_FOUND,
    );
    status(
        handle_inbound_sealed(
            State(h.ctx.clone()),
            Json(InboundSealedRequest {
                message_id: String::new(),
                sealed_inner: String::new(),
                origin_server: "127.0.0.1".into(),
                timestamp: 0,
                payload_hash: String::new(),
                server_signature: None,
            }),
        )
        .await,
        StatusCode::NOT_FOUND,
    );
    assert!(h.mailbox().await.is_empty());
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn hash_mismatch_unavailable_key_bad_ids_and_stale_time_do_not_claim() {
    let h = Harness::new().await;
    for sealed in [false, true] {
        let original = h.envelope(sealed);
        let mut bad_hash = original.clone();
        bad_hash.envelope.payload_hash = "wrong".into();
        status(
            h.receive(sealed, bad_hash.clone(), Some(h.signed(&bad_hash)))
                .await,
            StatusCode::BAD_REQUEST,
        );
        assert!(!h.claimed(&bad_hash).await);
        let mut unknown = original.clone();
        unknown.envelope.origin_server = "unavailable.example".into();
        status(
            h.receive(sealed, unknown.clone(), Some(h.signed(&unknown)))
                .await,
            StatusCode::BAD_GATEWAY,
        );
        assert!(!h.claimed(&unknown).await);
        for timestamp in [0, u64::MAX] {
            let mut stale = original.clone();
            stale.envelope.timestamp = timestamp;
            status(
                h.receive(sealed, stale.clone(), Some(h.signed(&stale)))
                    .await,
                StatusCode::UNAUTHORIZED,
            );
            assert!(!h.claimed(&stale).await);
        }
        for id in [String::new(), "x".repeat(129)] {
            let mut bad_id = original.clone();
            bad_id.envelope.message_id = id;
            status(
                h.receive(sealed, bad_id.clone(), Some(h.signed(&bad_id)))
                    .await,
                StatusCode::BAD_REQUEST,
            );
            assert!(!h.claimed(&bad_id).await);
        }
        assert!(h.mailbox().await.is_empty());
    }
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn unavailable_claim_store_fails_closed_before_dispatch() {
    let mut h = Harness::new().await;
    let proxy = crate::sealed_matrix_tests::CuttableRedis::start().await;
    let live = h.ctx.redis_conn.clone();
    Arc::get_mut(&mut h.ctx).unwrap().redis_conn =
        construct_redis::connect_manager(&proxy.url).await.unwrap();
    proxy.cut();
    for sealed in [false, true] {
        let req = h.envelope(sealed);
        status(
            h.receive(sealed, req.clone(), Some(h.signed(&req))).await,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        assert!(
            !live
                .clone()
                .exists::<_, bool>(Harness::claim_key(&req))
                .await
                .unwrap()
        );
        let len: usize = live
            .clone()
            .xlen(format!("delivery:offline:{}", h.recipient))
            .await
            .unwrap();
        assert_eq!(len, 0, "Redis outage bypassed the federation replay guard");
    }
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn sealed_signature_cannot_be_used_on_regular_endpoint_to_burn_its_claim() {
    let h = Harness::new().await;
    let sealed = h.envelope(true);
    let signature = h.signed(&sealed);
    status(
        h.receive(false, sealed.clone(), Some(signature.clone()))
            .await,
        StatusCode::BAD_REQUEST,
    );
    assert!(
        !h.claimed(&sealed).await,
        "wrong endpoint burned the sealed message's claim"
    );
    let (_, Json(response)) = h
        .receive(true, sealed.clone(), Some(signature))
        .await
        .unwrap();
    assert_eq!(response.status, "accepted");
    assert_eq!(h.mailbox().await.len(), 1);
    h.cleanup(&[sealed]).await;
}

#[tokio::test]
#[ignore = "requires Redis and Postgres"]
async fn concurrent_retries_have_one_winner_and_one_mailbox_write() {
    let h = Harness::new().await;
    for sealed in [false, true] {
        let request = h.envelope(sealed);
        let signature = h.signed(&request);
        let (a, b) = tokio::join!(
            h.receive(sealed, request.clone(), Some(signature.clone())),
            h.receive(sealed, request.clone(), Some(signature)),
        );
        let mut outcomes = [a.unwrap().1.0.status, b.unwrap().1.0.status];
        outcomes.sort();
        assert_eq!(outcomes, ["accepted", "duplicate"]);
        assert_eq!(h.mailbox().await.len(), 1);
        h.cleanup(&[request]).await;
    }
}
