//! Registration, sign-in, refresh and sign-out, through the RPCs a client calls.
//!
//! These decide who is handed a token.
use super::*;
use proto::auth_service_server::AuthService;
use sha2::{Digest, Sha256};

fn device_id(identity_public: &[u8]) -> String {
    hex::encode(&Sha256::digest(identity_public)[..16])
}

/// The client's side of the puzzle, written against the parameters and not by calling the
/// verifier it is checked with.
fn hash(challenge: &str, nonce: u64) -> Vec<u8> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let salt = format!("kpow2:{}", &challenge[..16]);
    let mut out = vec![0; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(32 * 1024, 2, 1, Some(32)).unwrap(),
    )
    .hash_password_into(
        format!("{challenge}{nonce}").as_bytes(),
        salt.as_bytes(),
        &mut out,
    )
    .unwrap();
    out
}

fn zero_bits(hash: &[u8]) -> u32 {
    let first = hash.iter().position(|b| *b != 0).unwrap_or(hash.len());
    first as u32 * 8 + hash.get(first).map_or(0, |b| b.leading_zeros())
}

fn solve(challenge: &str, difficulty: u32) -> proto::PowSolution {
    (0..)
        .map(|nonce| (nonce, hash(challenge, nonce)))
        .find(|(_, h)| zero_bits(h) >= difficulty)
        .map(|(nonce, h)| proto::PowSolution {
            challenge: challenge.to_string(),
            nonce,
            hash: hex::encode(h),
        })
        .unwrap()
}

impl Fixture {
    async fn challenge(&mut self, difficulty: i16) -> String {
        let challenge = construct_pow::generate_challenge();
        self.service
            .context
            .queue
            .lock()
            .await
            .create_pow_challenge(&challenge, difficulty, None, 600)
            .await
            .unwrap();
        self.keys.push(format!("pow:ch:{challenge}"));
        challenge
    }

    async fn spent(&self, challenge: &str) -> bool {
        self.service
            .context
            .queue
            .lock()
            .await
            .get_pow_challenge(challenge)
            .await
            .unwrap()
            .is_none_or(|c| c.used)
    }

    async fn registers(
        &mut self,
        request: proto::RegisterDeviceRequest,
    ) -> Result<proto::AuthTokensResponse, Status> {
        let tokens = self
            .service
            .register_device(Request::new(request))
            .await?
            .into_inner()
            .tokens
            .unwrap();
        self.users.push(tokens.user_id.parse().unwrap());
        Ok(tokens)
    }

    async fn accounts_with(&self, device: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE device_id = $1")
            .bind(device)
            .fetch_one(self.service.context.db_pool.as_ref())
            .await
            .unwrap()
    }

    /// A registered device with the key it signs in with.
    async fn registered(&mut self) -> (proto::AuthTokensResponse, String, SigningKey) {
        let challenge = self.challenge(0).await;
        let (key, request) = registration(solve(&challenge, 0));
        let device = request.device_id.clone();
        let tokens = self.registers(request).await.unwrap();
        self.keys
            .extend([format!("rate:login:{device}"), format!("blocked:{device}")]);
        (tokens, device, key)
    }

    async fn sign_in(
        &self,
        device: &str,
        key: &SigningKey,
        timestamp: i64,
    ) -> Result<proto::AuthTokensResponse, Status> {
        let signature = key.sign(format!("{device}{timestamp}").as_bytes());
        Ok(self
            .service
            .authenticate_device(Request::new(proto::AuthenticateDeviceRequest {
                device_id: device.to_string(),
                timestamp,
                signature: signature.to_bytes().to_vec(),
            }))
            .await?
            .into_inner()
            .tokens
            .unwrap())
    }

    async fn refresh(&self, token: &str) -> Result<proto::RefreshTokenResponse, Status> {
        Ok(self
            .service
            .refresh_token(Request::new(proto::RefreshTokenRequest {
                refresh_token: token.to_string(),
                ..Default::default()
            }))
            .await?
            .into_inner())
    }

    async fn accepts(&self, token: &str) -> bool {
        self.service
            .verify_token(Request::new(proto::VerifyTokenRequest {
                access_token: token.to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .valid
    }

    async fn logout(&mut self, token: &str, all_devices: bool) {
        let claims = self
            .service
            .context
            .auth_manager
            .verify_token(token)
            .unwrap();
        self.keys.push(format!("invalidated_token:{}", claims.jti));
        self.service
            .logout(Request::new(proto::LogoutRequest {
                access_token: token.to_string(),
                all_devices,
            }))
            .await
            .unwrap();
    }
}

fn registration(pow: proto::PowSolution) -> (SigningKey, proto::RegisterDeviceRequest) {
    let (key, public) = device_keys();
    let request = proto::RegisterDeviceRequest {
        device_id: device_id(&public.identity_public),
        public_keys: Some(public),
        pow_solution: Some(pow),
        ..Default::default()
    };
    (key, request)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn one_solution_opens_one_account_even_when_spent_at_once() {
    let mut f = Fixture::new().await;
    let challenge = f.challenge(0).await;
    let pow = solve(&challenge, 0);
    // Separate instances: one process's queue mutex would hide what Redis alone must decide.
    let start = Arc::new(tokio::sync::Barrier::new(6));
    let mut calls = Vec::new();
    for _ in 0..6 {
        let (other, request) = (Fixture::new().await, registration(pow.clone()).1);
        let start = start.clone();
        calls.push(tokio::spawn(async move {
            start.wait().await;
            other.service.register_device(Request::new(request)).await
        }));
    }
    let mut opened = 0;
    let mut refused = Vec::new();
    for call in calls {
        match call.await.unwrap() {
            Ok(r) => {
                opened += 1;
                let tokens = r.into_inner().tokens.unwrap();
                f.users.push(tokens.user_id.parse().unwrap());
            }
            Err(e) => refused.push(e.code()),
        }
    }
    f.cleanup().await;
    assert_eq!(opened, 1, "refused: {refused:?}");
    assert!(
        refused.iter().all(|c| *c == Code::InvalidArgument),
        "{refused:?}"
    );
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_timestamp_that_overflows_the_window_is_refused() {
    let mut f = Fixture::new().await;
    let (_, device, key) = f.registered().await;
    let mut codes = Vec::new();
    for t in [i64::MIN, i64::MAX, i64::MIN + now()] {
        codes.push(
            f.sign_in(&device, &key, t)
                .await
                .map(|_| ())
                .map_err(|e| e.code()),
        );
    }
    f.cleanup().await;
    assert_eq!(codes, [Err(Code::InvalidArgument); 3]);
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn registration_stores_the_device_and_hands_out_tokens_bound_to_it() {
    let mut f = Fixture::new().await;
    let challenge = f.challenge(1).await;
    let (_, mut request) = registration(solve(&challenge, 1));
    // A suite whose name tries to close the JSON string and add one of its own.
    request.public_keys.as_mut().unwrap().crypto_suite = "a\",\"b".into();
    let keys = request.public_keys.clone().unwrap();
    let device = request.device_id.clone();
    let tokens = f.registers(request.clone()).await.unwrap();
    let user: Uuid = tokens.user_id.parse().unwrap();

    let pool = f.service.context.db_pool.clone();
    let row = construct_db::get_device_by_id(&pool, &device)
        .await
        .unwrap()
        .unwrap();
    let primary = construct_db::get_user_by_id(&pool, &user)
        .await
        .unwrap()
        .unwrap()
        .primary_device_id;
    let auth = f.service.context.auth_manager.clone();
    let access = auth.verify_token(&tokens.access_token).unwrap();
    let refresh = auth.verify_token(&tokens.refresh_token).unwrap();
    let mut redis = redis_of(&f).await;
    let owner: Option<String> = get(&mut redis, &format!("refresh_token:{}", refresh.jti)).await;
    let indexed: bool = redis::cmd("SISMEMBER")
        .arg(format!("user_tokens:{user}"))
        .arg(&refresh.jti)
        .query_async(&mut redis)
        .await
        .unwrap();
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("refresh_token:{}", refresh.jti))
        .query_async(&mut redis)
        .await
        .unwrap();
    let challenge_left: Option<String> = get(&mut redis, &format!("pow:ch:{challenge}")).await;
    // The same solution for another device, and the same device with another solution.
    let replay = f
        .registers(registration(request.pow_solution.clone().unwrap()).1)
        .await;
    let again = f.challenge(0).await;
    request.pow_solution = Some(solve(&again, 0));
    let duplicate = f.registers(request).await;
    let accounts = f.accounts_with(&device).await;
    f.cleanup().await;

    assert_eq!(row.user_id, Some(user));
    assert!(row.is_active);
    assert_eq!(row.verifying_key, keys.verifying_key);
    assert_eq!(row.identity_public, keys.identity_public);
    assert_eq!(row.signed_prekey_public, keys.signed_prekey_public);
    assert_eq!(
        row.signed_prekey_signature,
        Some(keys.signed_prekey_signature)
    );
    assert_eq!(row.crypto_suites, serde_json::json!(["a\",\"b"]));
    assert_eq!(primary.as_deref(), Some(&device[..]));
    for claims in [&access, &refresh] {
        assert_eq!(claims.sub, user.to_string());
        assert_eq!(claims.device_id.as_deref(), Some(&device[..]));
    }
    assert!(
        (tokens.expires_at - access.exp).abs() <= 2,
        "expiry on the wire is the token's"
    );
    assert_eq!(owner, Some(user.to_string()));
    assert!(
        indexed,
        "sign-out everywhere finds tokens through this index"
    );
    assert!((90 * 86_400 - 60..=90 * 86_400).contains(&ttl), "{ttl}");
    assert_eq!(challenge_left, None, "a spent challenge is gone");
    assert_eq!(replay.unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(duplicate.unwrap_err().code(), Code::AlreadyExists);
    assert_eq!(accounts, 1);
}

async fn redis_of(f: &Fixture) -> redis::aio::MultiplexedConnection {
    redis::Client::open(f.service.context.config.redis_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

async fn get(redis: &mut redis::aio::MultiplexedConnection, key: &str) -> Option<String> {
    redis::cmd("GET").arg(key).query_async(redis).await.unwrap()
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_solution_must_answer_a_live_challenge_at_its_difficulty() {
    let mut f = Fixture::new().await;
    let hard = f.challenge(64).await;
    let plain = f.challenge(0).await;
    let other = f.challenge(0).await;
    let solved = solve(&plain, 0);
    let expired = construct_pow::generate_challenge();
    let spent_by_an_old_server = construct_pow::generate_challenge();
    let mut redis = redis_of(&f).await;
    for (challenge, used, offset) in [(&expired, false, -1), (&spent_by_an_old_server, true, 60)] {
        let record = serde_json::json!({
            "difficulty": 0, "used": used, "requester_ip": null,
            "expires_at": chrono::Utc::now() + chrono::Duration::seconds(offset),
        });
        let _: () = redis::cmd("SET")
            .arg(format!("pow:ch:{challenge}"))
            .arg(record.to_string())
            .arg("EX")
            .arg(60)
            .query_async(&mut redis)
            .await
            .unwrap();
        f.keys.push(format!("pow:ch:{challenge}"));
    }
    let cases = [
        ("too easy", solve(&hard, 0)),
        (
            "never issued",
            solve(&construct_pow::generate_challenge(), 0),
        ),
        ("expired", solve(&expired, 0)),
        ("marked used", solve(&spent_by_an_old_server, 0)),
        (
            "another challenge's answer",
            proto::PowSolution {
                challenge: other.clone(),
                ..solved.clone()
            },
        ),
        (
            "another nonce",
            proto::PowSolution {
                nonce: solved.nonce + 1,
                ..solved.clone()
            },
        ),
    ];
    let mut got = Vec::new();
    for (name, pow) in cases {
        let (_, request) = registration(pow);
        let device = request.device_id.clone();
        let code = f.registers(request).await.map(|_| ()).map_err(|e| e.code());
        got.push((name, code, f.accounts_with(&device).await));
    }
    let untouched = [
        f.spent(&hard).await,
        f.spent(&plain).await,
        f.spent(&other).await,
    ];
    f.cleanup().await;
    for (name, code, accounts) in got {
        assert_eq!((code, accounts), (Err(Code::InvalidArgument), 0), "{name}");
    }
    assert_eq!(untouched, [false; 3], "a refused solution spends nothing");
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn malformed_registrations_are_refused_before_the_solution_is_spent() {
    let mut f = Fixture::new().await;
    let challenge = f.challenge(0).await;
    let pow = solve(&challenge, 0);
    type Break = fn(&mut proto::RegisterDeviceRequest);
    let cases: [(&str, Break); 14] = [
        ("short id", |r| r.device_id.truncate(31)),
        ("upper case id", |r| r.device_id = "AB".repeat(16)),
        ("not hex", |r| r.device_id = "zz".repeat(16)),
        ("another key's id", |r| r.device_id = device_id(&[1; 32])),
        ("name too short", |r| r.username = Some("ab".into())),
        ("name too long", |r| r.username = Some("a".repeat(21))),
        ("name with a space", |r| r.username = Some("a b".into())),
        ("no keys", |r| r.public_keys = None),
        ("suite too long", |r| keys(r).crypto_suite = "s".repeat(65)),
        ("short identity key", |r| {
            keys(r).identity_public = vec![7; 31];
            r.device_id = device_id(&[7; 31]);
        }),
        ("long identity key", |r| {
            keys(r).identity_public = vec![7; 33];
            r.device_id = device_id(&[7; 33]);
        }),
        ("prekey the signature does not cover", |r| {
            keys(r).signed_prekey_public[0] ^= 1
        }),
        ("broken signature", |r| {
            keys(r).signed_prekey_signature[0] ^= 1
        }),
        ("short verifying key", |r| {
            keys(r).verifying_key.truncate(31)
        }),
    ];
    let mut got = Vec::new();
    for (name, break_it) in cases {
        let (_, mut request) = registration(pow.clone());
        break_it(&mut request);
        got.push((
            name,
            f.registers(request).await.map(|_| ()).map_err(|e| e.code()),
        ));
    }
    // Correctly signed, so that only the length is wrong.
    for len in [31, 33] {
        let (key, mut request) = registration(pow.clone());
        let spk = vec![9; len];
        let mut body = b"KonstruktX3DH-v1\x00\x01".to_vec();
        body.extend_from_slice(&spk);
        keys(&mut request).signed_prekey_signature = key.sign(&body).to_bytes().to_vec();
        keys(&mut request).signed_prekey_public = spk;
        got.push((
            "prekey length",
            f.registers(request).await.map(|_| ()).map_err(|e| e.code()),
        ));
    }
    let spent = f.spent(&challenge).await;
    // The controls: the edges that are inside, on the very solution nothing above spent.
    let (_, mut edge) = registration(pow);
    keys(&mut edge).crypto_suite = "s".repeat(64);
    edge.username = Some(format!("u{}", &Uuid::new_v4().simple().to_string()[..19]));
    let edge = f
        .registers(edge)
        .await
        .map(|_| ())
        .map_err(|e| e.message().to_string());
    f.cleanup().await;
    for (name, code) in got {
        assert_eq!(code, Err(Code::InvalidArgument), "{name}");
    }
    assert!(!spent);
    assert_eq!(edge, Ok(()));
}

fn keys(r: &mut proto::RegisterDeviceRequest) -> &mut proto::DevicePublicKeys {
    r.public_keys.as_mut().unwrap()
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_name_belongs_to_one_account_whatever_its_case() {
    let mut f = Fixture::new().await;
    let name = format!("u{}", &Uuid::new_v4().simple().to_string()[..10]);
    let mut results = Vec::new();
    for spelling in [name.clone(), name.to_uppercase()] {
        let challenge = f.challenge(0).await;
        let (_, mut request) = registration(solve(&challenge, 0));
        request.username = Some(spelling);
        results.push(f.registers(request).await.map(|_| ()).map_err(|e| e.code()));
    }
    f.cleanup().await;
    assert_eq!(results, [Ok(()), Err(Code::AlreadyExists)]);
}

/// Register while another transaction holds the same name or device, not yet committed: the
/// reads before the insert miss it, the unique index does not. Commits once Postgres says the
/// registration is waiting for it, so the order does not depend on timing.
async fn register_against_an_uncommitted(
    f: &mut Fixture,
    request: proto::RegisterDeviceRequest,
    insert: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
) -> Status {
    let pool = f.service.context.db_pool.clone();
    let mut tx = pool.begin().await.unwrap();
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    insert.execute(&mut *tx).await.unwrap();
    let other = Fixture::new().await;
    let call =
        tokio::spawn(async move { other.service.register_device(Request::new(request)).await });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(holder)
        .fetch_one(pool.as_ref())
        .await
        .unwrap()
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the registration must reach the index and wait there");
    tx.commit().await.unwrap();
    call.await
        .unwrap()
        .expect_err("the row was committed first")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_name_taken_between_the_read_and_the_insert_is_refused_by_name() {
    let mut f = Fixture::new().await;
    let name = format!("u{}", &Uuid::new_v4().simple().to_string()[..10]);
    let secret = f
        .service
        .context
        .config
        .security
        .username_hmac_secret
        .clone();
    let hash = construct_crypto::hash_username(&secret, &name);
    let owner = Uuid::new_v4();
    f.users.push(owner);
    let challenge = f.challenge(0).await;
    let (_, mut request) = registration(solve(&challenge, 0));
    request.username = Some(name);
    let insert = sqlx::query("INSERT INTO users (id, username_hash) VALUES ($1, $2)")
        .bind(owner)
        .bind(&hash);
    let refused = register_against_an_uncommitted(&mut f, request, insert).await;
    f.cleanup().await;
    assert_eq!(
        (refused.code(), refused.message()),
        (Code::AlreadyExists, "Username is already taken")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_device_registered_between_the_read_and_the_insert_is_refused_by_name() {
    let mut f = Fixture::new().await;
    let owner = f.user().await;
    let challenge = f.challenge(0).await;
    let (_, request) = registration(solve(&challenge, 0));
    let device = request.device_id.clone();
    let insert = sqlx::query(
        "INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                              identity_public, signed_prekey_public, registered_at)
         VALUES ($1, $2, 'test.local', $3, $4, $5, NOW())",
    )
    .bind(&device)
    .bind(owner)
    .bind(vec![1u8; 32])
    .bind(Uuid::new_v4().as_bytes().repeat(2))
    .bind(vec![3u8; 32]);
    let refused = register_against_an_uncommitted(&mut f, request, insert).await;
    f.cleanup().await;
    assert_eq!(
        (refused.code(), refused.message()),
        (Code::AlreadyExists, "Device already exists")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn an_identity_key_registered_between_the_read_and_the_insert_is_refused_by_name() {
    let mut f = Fixture::new().await;
    let owner = f.user().await;
    let challenge = f.challenge(0).await;
    let (_, request) = registration(solve(&challenge, 0));
    let identity = request
        .public_keys
        .as_ref()
        .unwrap()
        .identity_public
        .clone();
    let other_id = Uuid::new_v4().simple().to_string();
    let insert = sqlx::query(
        "INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                              identity_public, signed_prekey_public, registered_at)
         VALUES ($1, $2, 'test.local', $3, $4, $5, NOW())",
    )
    .bind(&other_id)
    .bind(owner)
    .bind(vec![1u8; 32])
    .bind(&identity)
    .bind(vec![3u8; 32]);
    let refused = register_against_an_uncommitted(&mut f, request, insert).await;
    f.cleanup().await;
    assert_eq!(refused.code(), Code::AlreadyExists);
    assert!(refused.message().starts_with("Identity key"), "{refused:?}");
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn signing_in_takes_the_devices_own_key_inside_five_minutes() {
    let mut f = Fixture::new().await;
    let (registered, device, key) = f.registered().await;
    let (_, other_device, other_key) = f.registered().await;
    let t = now();
    let inside = [
        f.sign_in(&device, &key, t - 295).await,
        f.sign_in(&device, &key, t + 295).await,
    ];
    let outside = [
        f.sign_in(&device, &key, t - 310).await,
        f.sign_in(&device, &key, t + 310).await,
    ];
    // A valid signature of another device, and one over another moment.
    let foreign = f.sign_in(&device, &other_key, t).await;
    let moved = f
        .service
        .authenticate_device(Request::new(proto::AuthenticateDeviceRequest {
            device_id: device.clone(),
            timestamp: t,
            signature: key
                .sign(format!("{device}{}", t - 1).as_bytes())
                .to_bytes()
                .to_vec(),
        }))
        .await;
    let short = f
        .service
        .authenticate_device(Request::new(proto::AuthenticateDeviceRequest {
            device_id: device.clone(),
            timestamp: t,
            signature: vec![0; 63],
        }))
        .await;
    let auth = f.service.context.auth_manager.clone();
    let mut redis = redis_of(&f).await;
    let mut owners = Vec::new();
    let mut claims = Vec::new();
    for tokens in inside {
        let tokens = tokens.unwrap();
        let refresh = auth.verify_token(&tokens.refresh_token).unwrap();
        owners.push(get(&mut redis, &format!("refresh_token:{}", refresh.jti)).await);
        claims.push(auth.verify_token(&tokens.access_token).unwrap());
        claims.push(refresh);
    }
    let unknown = f.sign_in(&device_id(&[3; 32]), &key, t).await;
    sqlx::query("UPDATE devices SET is_active = FALSE WHERE device_id = $1")
        .bind(&other_device)
        .execute(f.service.context.db_pool.as_ref())
        .await
        .unwrap();
    let removed = f.sign_in(&other_device, &other_key, t).await;
    f.cleanup().await;

    for c in claims {
        assert_eq!(c.sub, registered.user_id);
        assert_eq!(c.device_id.as_deref(), Some(&device[..]));
    }
    assert_eq!(owners, vec![Some(registered.user_id.clone()); 2]);
    for refused in outside {
        assert_eq!(refused.unwrap_err().code(), Code::InvalidArgument);
    }
    assert_eq!(foreign.unwrap_err().code(), Code::Unauthenticated);
    assert_eq!(moved.unwrap_err().code(), Code::Unauthenticated);
    assert_eq!(short.unwrap_err().code(), Code::InvalidArgument);
    // The wipe signal: each refusal carries its own reason, and neither is the other's.
    let reason = |r: Result<proto::AuthTokensResponse, Status>| {
        let status = r.unwrap_err();
        let reason = status
            .metadata()
            .get("construct-device-refusal")
            .map(|v| v.to_str().unwrap().to_string());
        (status.code(), reason)
    };
    let (unknown, removed) = (reason(unknown), reason(removed));
    assert!(
        unknown.1.is_some() && removed.1.is_some(),
        "{unknown:?} {removed:?}"
    );
    assert_ne!(unknown, removed);
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn failures_are_counted_per_device_and_a_success_clears_them() {
    let mut f = Fixture::new().await;
    let (_, device, key) = f.registered().await;
    let (_, bystander, bystander_key) = f.registered().await;
    let wrong = SigningKey::from_bytes(&[77; 32]);
    for _ in 0..4 {
        f.sign_in(&device, &wrong, now()).await.unwrap_err();
    }
    let after_four = f.sign_in(&device, &key, now()).await.is_ok();
    let mut redis = redis_of(&f).await;
    let cleared = get(&mut redis, &format!("rate:login:{device}")).await;
    for _ in 0..5 {
        f.sign_in(&device, &wrong, now()).await.unwrap_err();
    }
    let blocked = f.sign_in(&device, &key, now()).await;
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("blocked:{device}"))
        .query_async(&mut redis)
        .await
        .unwrap();
    let other = f.sign_in(&bystander, &bystander_key, now()).await.is_ok();
    f.cleanup().await;
    assert!(after_four);
    assert_eq!(cleared, None);
    assert_eq!(blocked.unwrap_err().code(), Code::Unauthenticated);
    assert!((3590..=3600).contains(&ttl), "{ttl}");
    assert!(other, "another device is not counted");
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_refresh_token_is_spent_once_and_an_access_token_never_refreshes() {
    let mut f = Fixture::new().await;
    let (tokens, device, _) = f.registered().await;
    let by_access = f.refresh(&tokens.access_token).await;
    let first = f.refresh(&tokens.refresh_token).await.unwrap();
    let second = f.refresh(&tokens.refresh_token).await;
    let chained = f.refresh(first.refresh_token.as_deref().unwrap()).await;
    let claims = f
        .service
        .context
        .auth_manager
        .verify_token(&first.access_token)
        .unwrap();
    let garbage = f.refresh("v4.public.AAAA").await;
    f.cleanup().await;
    assert_eq!(by_access.unwrap_err().code(), Code::Unauthenticated);
    assert_eq!(second.unwrap_err().code(), Code::Unauthenticated);
    assert!(chained.is_ok());
    assert_eq!(claims.sub, tokens.user_id);
    assert_eq!(claims.device_id, Some(device));
    assert_eq!(garbage.unwrap_err().code(), Code::Unauthenticated);
}

/// The index names the account a refresh token was stored for; a token that claims another
/// must not be renewed on it.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_refresh_token_stored_for_another_account_is_refused() {
    let mut f = Fixture::new().await;
    let (tokens, _, _) = f.registered().await;
    let jti = f
        .service
        .context
        .auth_manager
        .verify_token(&tokens.refresh_token)
        .unwrap()
        .jti;
    let mut redis = redis_of(&f).await;
    let _: () = redis::cmd("SET")
        .arg(format!("refresh_token:{jti}"))
        .arg(Uuid::new_v4().to_string())
        .arg("EX")
        .arg(60)
        .query_async(&mut redis)
        .await
        .unwrap();
    let refused = f.refresh(&tokens.refresh_token).await;
    f.cleanup().await;
    assert_eq!(refused.unwrap_err().code(), Code::Unauthenticated);
}

#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn signing_out_everywhere_ends_every_refresh_token_and_this_access_token() {
    let mut f = Fixture::new().await;
    let (tokens, device, key) = f.registered().await;
    let again = f.sign_in(&device, &key, now()).await.unwrap();
    let (stranger, _, _) = f.registered().await;
    f.logout(&tokens.access_token, true).await;
    let access = f.accepts(&tokens.access_token).await;
    let first = f.refresh(&tokens.refresh_token).await;
    let second = f.refresh(&again.refresh_token).await;
    let bystander = f.refresh(&stranger.refresh_token).await;
    f.cleanup().await;
    assert!(!access);
    assert_eq!(first.unwrap_err().code(), Code::Unauthenticated);
    assert_eq!(second.unwrap_err().code(), Code::Unauthenticated);
    assert!(bystander.is_ok(), "another account is not signed out");
}
