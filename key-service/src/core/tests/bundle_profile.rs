//! Service-backed baseline for the real bundle builders, not for the outer gRPC handlers.
use super::*;
use anyhow::{Context, ensure};
use std::{future::Future, time::Instant};

#[path = "../../../../shared/test_support/allocations.rs"]
mod allocations;
#[path = "../../../../shared/test_support/postgres.rs"]
mod postgres;

#[derive(Default)]
struct Measurements {
    calls: usize,
    bytes: usize,
    peak: usize,
    cpu: f64,
    wall: f64,
}

fn cpu_seconds() -> Result<f64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is a writable timespec for the duration of the call.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read process CPU time");
    }
    Ok(time.tv_sec as f64 + time.tv_nsec as f64 * 1e-9)
}

impl Measurements {
    async fn fetch<T>(&mut self, fetch: impl Future<Output = Result<T>>) -> Result<T> {
        let cpu = cpu_seconds()?;
        let wall = Instant::now();
        let sample = allocations::AllocationSample::start();
        let result = fetch.await?;
        let allocations::AllocationDelta {
            calls,
            bytes,
            live,
            peak,
            peak_delta,
        } = sample.finish();
        self.wall += wall.elapsed().as_secs_f64();
        self.cpu += cpu_seconds()? - cpu;
        ensure!(
            calls > 0 && bytes > 0 && peak >= live,
            "allocator did not capture the fetch"
        );
        self.calls += calls;
        self.bytes += bytes;
        self.peak = self.peak.max(peak_delta);
        Ok(result)
    }

    fn print(&self, round: usize, mode: &str, consume: bool, count: usize) {
        let n = count as f64;
        println!(
            "pq_bundle: round={round} mode={mode} consume={consume} ops={count} allocations/op={:.3} requested_bytes/op={:.1} cpu_us/op={:.1} wall_us/op={:.1} peak_delta={}",
            self.calls as f64 / n,
            self.bytes as f64 / n,
            self.cpu * 1e6 / n,
            self.wall * 1e6 / n,
            self.peak
        );
    }
}

struct Device {
    id: String,
    identity: Vec<u8>,
    spk: KyberOneTimePreKey,
}

struct Keys {
    classic: OneTimePreKey,
    pq: KyberOneTimePreKey,
}

async fn seed_keys(db: &PgPool, device: &Device, signing: &SigningDevice, id: u32) -> Result<Keys> {
    let classic = OneTimePreKey {
        key_id: id,
        public_key: vec![id as u8; 32],
    };
    let pq = signing.kyber_key(id + 31, now_secs() - 30);
    assert_eq!(
        upload_prekeys(
            db,
            &device.id,
            std::slice::from_ref(&classic),
            false,
            std::slice::from_ref(&pq)
        )
        .await?,
        (1, 1),
        "one active key of each kind per device before the fetch"
    );
    Ok(Keys { classic, pq })
}

async fn assert_key_state(db: &PgPool, device_id: &str, keys: &Keys, consumed: bool) -> Result<()> {
    let classic: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT public_key FROM one_time_prekeys WHERE device_id=$1 AND key_id=$2",
    )
    .bind(device_id)
    .bind(keys.classic.key_id as i32)
    .fetch_optional(db)
    .await?;
    assert_eq!(
        classic.as_deref(),
        (!consumed).then_some(keys.classic.public_key.as_slice())
    );
    let (pq, expired, timestamp_set): (Vec<u8>, bool, bool) = sqlx::query_as(
        "SELECT public_key, is_expired, expired_at IS NOT NULL FROM kyber_one_time_pre_keys WHERE device_id=$1 AND key_id=$2",
    ).bind(device_id).bind(keys.pq.key_id as i32).fetch_one(db).await?;
    assert_eq!(
        (pq.as_slice(), expired, timestamp_set),
        (keys.pq.public_key.as_slice(), consumed, consumed)
    );
    assert_eq!(
        active_prekey_counts(db, device_id).await?,
        if consumed { (0, 0) } else { (1, 1) }
    );
    Ok(())
}

fn assert_bundle(
    bundle: &PreKeyBundle,
    device: &Device,
    signing: &SigningDevice,
    server: &SigningKey,
    keys: Option<&Keys>,
) -> Result<()> {
    assert_eq!(bundle.device_id, device.id);
    assert_eq!(bundle.identity_key, device.identity);
    assert_eq!(bundle.verifying_key, signing.verifying_key());
    assert_eq!(
        bundle.hybrid_identity_key.as_deref(),
        Some(signing.hybrid_pk.as_slice())
    );
    assert_eq!(bundle.kyber_pre_key_id, Some(device.spk.key_id));
    assert_eq!(bundle.kyber_pre_key_created_at, Some(device.spk.created_at));
    assert_eq!(
        bundle.kyber_pre_key.as_deref(),
        Some(device.spk.public_key.as_slice())
    );
    assert_eq!(
        bundle.kyber_pre_key_signature.as_deref(),
        Some(device.spk.signature.as_slice())
    );
    assert_eq!(
        bundle.kyber_pre_key_hybrid_signature.as_deref(),
        Some(device.spk.hybrid_signature.as_slice())
    );
    assert_eq!(bundle.one_time_prekey_id, keys.map(|k| k.classic.key_id));
    assert_eq!(
        bundle.one_time_prekey.as_deref(),
        keys.map(|k| k.classic.public_key.as_slice())
    );
    assert_eq!(bundle.kyber_one_time_pre_key_id, keys.map(|k| k.pq.key_id));
    assert_eq!(
        bundle.kyber_one_time_pre_key_created_at,
        keys.map(|k| k.pq.created_at)
    );
    assert_eq!(
        bundle.kyber_one_time_pre_key.as_deref(),
        keys.map(|k| k.pq.public_key.as_slice())
    );
    assert_eq!(
        bundle.kyber_one_time_pre_key_signature.as_deref(),
        keys.map(|k| k.pq.signature.as_slice())
    );
    assert_eq!(
        bundle.kyber_one_time_pre_key_hybrid_signature.as_deref(),
        keys.map(|k| k.pq.hybrid_signature.as_slice())
    );
    if keys.is_some() {
        let bytes = bundle.kyber_one_time_pre_key.as_deref().unwrap();
        let created_at = bundle.kyber_one_time_pre_key_created_at.unwrap();
        construct_crypto::pqc::verify_kyber_prekey_signature_v2(
            &bundle.verifying_key,
            created_at,
            bytes,
            bundle.kyber_one_time_pre_key_signature.as_deref().unwrap(),
        )?;
        construct_crypto::pqc::verify_hybrid_kyber_prekey_signature_v2(
            bundle.hybrid_identity_key.as_deref().unwrap(),
            created_at,
            bytes,
            bundle
                .kyber_one_time_pre_key_hybrid_signature
                .as_deref()
                .unwrap(),
        )?;
    }
    let signature = Signature::from_slice(
        bundle
            .bundle_signature
            .as_deref()
            .context("missing server signature")?,
    )?;
    server
        .verifying_key()
        .verify_strict(&canonical_bundle_bytes(bundle), &signature)?;
    ensure!(
        bundle.kt_proof.is_some() && bundle.hybrid_kt_proof.is_some(),
        "expected warmed KT path, not its fail-open branch"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires local disposable PostgreSQL, run alone"]
async fn profile_local_pq_bundles() -> Result<()> {
    let url =
        std::env::var("DATABASE_URL").context("DATABASE_URL required for PostgreSQL profile")?;
    let pg: sqlx::postgres::PgConnectOptions = url.parse()?;
    let host = pg.get_host();
    ensure!(
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
        "PostgreSQL must be loopback"
    );
    let db = postgres::Database::new(&sqlx::migrate!("../shared/migrations")).await;
    let pool = &db.pool;
    let signing = SigningDevice::new();
    let server = SigningKey::from_bytes(&[0x7e; 32]);
    let user: uuid::Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(pool)
        .await?;
    let user = user.to_string();
    let mut devices = Vec::new();
    for i in 0..3 {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let identity = vec![0x10 + i; 32];
        sqlx::query("INSERT INTO devices (device_id,user_id,server_hostname,verifying_key,identity_public,signed_prekey_public,hybrid_identity_key) VALUES ($1,$2::uuid,'test',$3,$4,$5,$6)")
            .bind(&id).bind(&user).bind(signing.verifying_key()).bind(&identity).bind(vec![0x20 + i; 32]).bind(&signing.hybrid_pk).execute(pool).await?;
        let spk = signing.kyber_key(1 + u32::from(i), now_secs() - 60);
        let mut conn = pool.acquire().await?;
        upload_kyber_signed_prekey(
            &mut conn,
            &id,
            spk.key_id,
            &spk.public_key,
            &spk.signature,
            spk.created_at,
            Some(&spk.hybrid_signature),
        )
        .await?;
        devices.push(Device { id, identity, spk });
    }
    let ids = devices.iter().map(|d| d.id.clone()).collect::<Vec<_>>();
    let sibling = seed_keys(pool, &devices[2], &signing, 100).await?;

    // Warm existing connections, prepared statements and first-time KT leaves; exclude
    // provisioning, verification and SQL state assertions from measured operations.
    for (round, count) in [(0, 3), (1, 16), (2, 16), (3, 16)] {
        for (batch, selected) in [(false, 1), (true, 2)] {
            let mut read_only = Measurements::default();
            let mut take = Measurements::default();
            for i in 0..count {
                let key_id = (1000 + 100 * round + 2 * i + 40 * usize::from(batch)) as u32;
                let mut keys = Vec::new();
                for (idx, device) in devices[..selected].iter().enumerate() {
                    keys.push(seed_keys(pool, device, &signing, key_id + idx as u32).await?);
                }
                for (consume, sample) in [(false, &mut read_only), (true, &mut take)] {
                    if batch {
                        let mut set = sample
                            .fetch(get_prekey_bundles(
                                pool,
                                &user,
                                Some(&ids[..selected]),
                                Some(&server),
                                None,
                                consume,
                            ))
                            .await?;
                        set.active_devices.sort_unstable();
                        let mut expected_ids = ids.clone();
                        expected_ids.sort_unstable();
                        assert_eq!(set.active_devices, expected_ids);
                        assert!(set.unavailable.is_empty());
                        assert_eq!(set.bundles.len(), selected);
                        for (device, keys) in devices[..selected].iter().zip(&keys) {
                            let bundle = set
                                .bundles
                                .iter()
                                .find(|b| b.device_id == device.id)
                                .context("missing bundle for requested device")?;
                            assert_bundle(
                                bundle,
                                device,
                                &signing,
                                &server,
                                consume.then_some(keys),
                            )?;
                        }
                    } else {
                        let bundle = sample
                            .fetch(get_prekey_bundle(
                                pool,
                                &user,
                                Some(&ids[0]),
                                Some(&server),
                                None,
                                consume,
                            ))
                            .await?
                            .context("missing single bundle")?;
                        assert_bundle(
                            &bundle,
                            &devices[0],
                            &signing,
                            &server,
                            consume.then_some(&keys[0]),
                        )?;
                    }
                    for (device, key) in devices[..selected].iter().zip(&keys) {
                        assert_key_state(pool, &device.id, key, consume).await?;
                    }
                    assert_key_state(pool, &devices[2].id, &sibling, false).await?;
                }
            }
            if round != 0 {
                let mode = if batch { "batch2" } else { "single" };
                read_only.print(round, mode, false, count);
                take.print(round, mode, true, count);
            }
        }
    }
    db.cleanup().await;
    Ok(())
}
