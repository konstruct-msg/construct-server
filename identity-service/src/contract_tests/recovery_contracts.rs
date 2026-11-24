//! Recovery hands the account to a new device in one step: all of it, or none of it.
use super::faulty_redis::FaultyRedis;
use super::*;

fn new_device_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// What a refused recovery must not touch.
#[derive(Debug, PartialEq)]
struct Account {
    active: Vec<String>,
    primary: Option<String>,
    recovered: bool,
    ml_dsa_key: Option<Vec<u8>>,
    marked: bool,
    signed_in: bool,
}

async fn account(f: &Fixture, user: Uuid, device: &str, refresh_jti: &str) -> Account {
    let db = f.service.context.db_pool.as_ref();
    let (primary, recovered, ml_dsa_key) = sqlx::query_as(
        "SELECT primary_device_id, last_recovery_at IS NOT NULL, recovery_mldsa_public_key \
         FROM users WHERE id = $1",
    )
    .bind(user)
    .fetch_one(db)
    .await
    .unwrap();
    let active = sqlx::query_scalar(
        "SELECT device_id FROM devices WHERE user_id = $1 AND is_active ORDER BY 1",
    )
    .bind(user)
    .fetch_all(db)
    .await
    .unwrap();
    let mut redis = redis::Client::open(f.service.context.config.redis_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let signed_in = redis::cmd("EXISTS")
        .arg(format!("refresh_token:{refresh_jti}"))
        .query_async(&mut redis)
        .await
        .unwrap();
    let mut queue = f.service.context.queue.lock().await;
    Account {
        active,
        primary,
        recovered,
        ml_dsa_key,
        marked: queue.is_device_revoked(device).await.unwrap(),
        signed_in,
    }
}

/// An account with one signed-in primary device. Returns the device and its refresh token's id.
async fn signed_in_account(f: &mut Fixture) -> (Uuid, String, String) {
    let user = f.user().await;
    let (device, _, _) = f.device(user).await;
    f.keys.push(format!("revoked_device:{device}"));
    construct_db::set_primary_device(f.service.context.db_pool.as_ref(), &user, &device)
        .await
        .unwrap();
    let jti = Uuid::new_v4().to_string();
    f.service
        .context
        .queue
        .lock()
        .await
        .store_refresh_token(&jti, &user.to_string(), 600)
        .await
        .unwrap();
    (user, device, jti)
}

/// Everything a recovery is refused for is found before it takes the account's devices away.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_refused_recovery_leaves_the_account_as_it_was() {
    let mut f = Fixture::new().await;
    let (user, device, jti) = signed_in_account(&mut f).await;
    // Removed before it had a marker, or after its marker ran out.
    let (removed_earlier, _, _) = f.device(user).await;
    f.keys.push(format!("revoked_device:{removed_earlier}"));
    sqlx::query("UPDATE devices SET is_active = FALSE WHERE device_id = $1")
        .bind(&removed_earlier)
        .execute(f.service.context.db_pool.as_ref())
        .await
        .unwrap();
    let neighbour = f.user().await;
    let (taken_id, _, taken_keys) = f.device(neighbour).await;
    let phrase = Phrase::of(&f, user).await;
    let before = account(&f, user, &device, &jti).await;

    let mut unsigned_prekey = device_keys().1;
    unsigned_prekey.signed_prekey_signature = vec![0; 64];
    let mut outcomes = Vec::new();
    for (case, id, keys) in [
        (
            "prekey not signed by the device",
            new_device_id(),
            unsigned_prekey,
        ),
        ("device id of another account", taken_id, device_keys().1),
        (
            "device id the account already has",
            device.clone(),
            device_keys().1,
        ),
        (
            "identity key of another device",
            new_device_id(),
            taken_keys,
        ),
    ] {
        let code = f
            .service
            .recover_account(Request::new(phrase.claim(user, &id, keys)))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        outcomes.push((case, code, account(&f, user, &device, &jti).await == before));
    }

    let (id, keys) = (new_device_id(), device_keys().1);
    let recovered = f
        .service
        .recover_account(Request::new(phrase.claim(user, &id, keys)))
        .await
        .map(Response::into_inner);
    let after = account(&f, user, &device, &jti).await;
    let hostname: Option<String> =
        sqlx::query_scalar("SELECT server_hostname FROM devices WHERE device_id = $1")
            .bind(&id)
            .fetch_optional(f.service.context.db_pool.as_ref())
            .await
            .unwrap();
    let earlier_marked = f
        .service
        .context
        .queue
        .lock()
        .await
        .is_device_revoked(&removed_earlier)
        .await
        .unwrap();
    let domain = f.service.context.config.instance_domain.clone();
    f.cleanup().await;

    assert_eq!(
        outcomes,
        [
            (
                "prekey not signed by the device",
                Code::InvalidArgument,
                true
            ),
            ("device id of another account", Code::AlreadyExists, true),
            (
                "device id the account already has",
                Code::AlreadyExists,
                true
            ),
            ("identity key of another device", Code::AlreadyExists, true),
        ]
    );
    assert_eq!(
        recovered.expect("the phrase still works").devices_revoked,
        1
    );
    assert_eq!(
        after,
        Account {
            active: vec![id.clone()],
            primary: Some(id),
            recovered: true,
            ml_dsa_key: before.ml_dsa_key,
            marked: true,
            signed_in: false,
        }
    );
    assert!(earlier_marked);
    assert_eq!(hostname, Some(domain));
}

/// A store that fails on the way leaves the rows as they were, so the phrase works again: the
/// seven days' wait starts with a recovery that happened.
#[tokio::test]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn a_recovery_the_store_interrupts_can_be_tried_again() {
    for (failing, has_session) in [
        ("revoked_device:", true),
        ("user_tokens:", true),
        ("refresh_token:", true),
        // Not knowing which sessions there are is not having ended them.
        ("SMEMBERS", true),
        // With no session to end, the first to fail is storing the new one.
        ("refresh_token:", false),
    ] {
        let mut config = test_config::config();
        let proxy = FaultyRedis::start(&config.redis_url).await;
        config.redis_url = proxy.url.clone();
        let mut f = Fixture::on(config).await;
        let (user, device, jti) = signed_in_account(&mut f).await;
        if !has_session {
            f.service
                .context
                .queue
                .lock()
                .await
                .revoke_all_user_tokens(&user.to_string())
                .await
                .unwrap();
        }
        let phrase = Phrase::of(&f, user).await;
        let before = account(&f, user, &device, &jti).await;

        proxy.fail_commands_naming(failing);
        let refused = f
            .service
            .recover_account(Request::new(phrase.claim(
                user,
                &new_device_id(),
                device_keys().1,
            )))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        proxy.recover();
        let between = account(&f, user, &device, &jti).await;

        let id = new_device_id();
        let again = f
            .service
            .recover_account(Request::new(phrase.claim(user, &id, device_keys().1)))
            .await
            .map_or_else(|e| e.code(), |_| Code::Ok);
        let after = account(&f, user, &device, &jti).await;
        f.cleanup().await;

        assert_eq!(refused, Code::Internal, "{failing} {has_session}");
        assert_eq!(between.active, before.active, "{failing} {has_session}");
        assert_eq!(between.primary, before.primary, "{failing} {has_session}");
        assert!(!between.recovered, "{failing} {has_session}");
        assert_eq!(again, Code::Ok, "{failing} {has_session}");
        assert_eq!(after.active, [id], "{failing} {has_session}");
        assert!(after.marked && !after.signed_in, "{failing}: {after:?}");
    }
}

/// Two devices with the same phrase at the same moment: one has the account, the other is told
/// to wait, and the account's device is the one that was told it has it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Redis and migrated PostgreSQL"]
async fn one_of_several_recoveries_at_once_gets_the_account() {
    let mut f = Fixture::new().await;
    let (user, _, _) = signed_in_account(&mut f).await;
    let phrase = Phrase::of(&f, user).await;
    let start = Arc::new(tokio::sync::Barrier::new(6));
    let mut calls = Vec::new();
    for _ in 0..6 {
        let id = new_device_id();
        f.keys.push(format!("revoked_device:{id}"));
        let claim = phrase.claim(user, &id, device_keys().1);
        let (other, start) = (Fixture::new().await, start.clone());
        calls.push(tokio::spawn(async move {
            start.wait().await;
            let code = other
                .service
                .recover_account(Request::new(claim))
                .await
                .map_or_else(|e| e.code(), |_| Code::Ok);
            (code, id)
        }));
    }
    let mut won = Vec::new();
    let mut refused = Vec::new();
    for call in calls {
        match call.await.unwrap() {
            (Code::Ok, id) => won.push(id),
            (code, _) => refused.push(code),
        }
    }
    let active: Vec<String> =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 AND is_active")
            .bind(user)
            .fetch_all(f.service.context.db_pool.as_ref())
            .await
            .unwrap();
    let mut marked = false;
    for id in &won {
        marked |= f
            .service
            .context
            .queue
            .lock()
            .await
            .is_device_revoked(id)
            .await
            .unwrap();
    }
    f.cleanup().await;

    assert_eq!(refused, [Code::ResourceExhausted; 5]);
    assert_eq!(won.len(), 1);
    assert_eq!(active, won);
    assert!(!marked, "the new device is out of messaging");
}
