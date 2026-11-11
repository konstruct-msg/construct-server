// ============================================================================
// Token Management
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_redis::RedisClient;

/// Redis key of the blocklist entry for one access token. Written by logout, read by every service
/// that has Redis (`construct_server_shared::revocation`, messaging's `extract_authed_identity`).
pub fn invalidated_token_key(jti: &str) -> String {
    format!("invalidated_token:{jti}")
}

/// Redis key of the per-device revocation marker. Written by every path that takes a device out of
/// service, read by messaging before it delivers (`extract_authed_identity`, `poll_messages`).
pub fn revoked_device_key(device_id: &str) -> String {
    format!("revoked_device:{device_id}")
}

/// Where the two markers that can kill one access token stand.
///
/// They are two keys because they answer two different questions — this token was logged out
/// (`invalidated_token:{jti}`) versus every token of this device is dead (`revoked_device:{device}`)
/// — and both are asked on every authenticated call. Reading them one after the other cost two
/// round trips on the cheapest operation the service has, so they are read together and split
/// apart here, where the caller can still say which one refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlocklistStanding {
    /// `invalidated_token:{jti}` is set: this access token was logged out.
    pub token_invalidated: bool,
    /// `revoked_device:{device}` is set: every token of this device is dead.
    pub device_revoked: bool,
}

impl BlocklistStanding {
    /// Whether anything in the answer should stop the caller.
    pub fn is_revoked(&self) -> bool {
        self.token_invalidated || self.device_revoked
    }
}

/// Map one `MGET` reply onto [`BlocklistStanding`].
///
/// `MGET` answers one element per key, `nil` for a key that does not exist — which is exactly what
/// `EXISTS` said about it, so a present-but-empty value still counts as set. Slot 0 is the token
/// blocklist; slot 1 is the device marker and is only read when a device was asked about at all.
fn standing_from_reply(names_a_device: bool, reply: &[Option<String>]) -> BlocklistStanding {
    BlocklistStanding {
        token_invalidated: reply.first().is_some_and(Option::is_some),
        device_revoked: names_a_device && reply.get(1).is_some_and(Option::is_some),
    }
}

/// Read both blocklist markers for one credential in a single round trip.
///
/// An empty `device_id` is no device (the same rule `normalize_device_id` applies on the delivery
/// path): a token that names none is asked about its own blocklist entry only, so a device marker
/// that cannot be read does not affect it. Any failure is an `Err` and the caller must close —
/// an unreadable blocklist is not a clean one.
pub async fn blocklist_standing(
    conn: &mut redis::aio::ConnectionManager,
    jti: &str,
    device_id: Option<&str>,
) -> Result<BlocklistStanding> {
    let token_key = invalidated_token_key(jti);
    let device_key = device_id.filter(|d| !d.is_empty()).map(revoked_device_key);

    let mut cmd = redis::cmd("MGET");
    cmd.arg(token_key.as_str());
    if let Some(key) = device_key.as_deref() {
        cmd.arg(key);
    }
    let reply: Vec<Option<String>> = cmd.query_async(conn).await?;

    Ok(standing_from_reply(device_key.is_some(), &reply))
}

pub(crate) struct TokenManager<'a> {
    client: &'a mut RedisClient,
}

impl<'a> TokenManager<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    /// Store refresh token in Redis for validation and revocation.
    /// Also registers the JTI in the per-user reverse index (user_tokens:{user_id})
    /// so that revoke_all_user_tokens can work without a KEYS scan.
    pub(crate) async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("refresh_token:{}", jti);
        let index_key = format!("user_tokens:{}", user_id);
        self.client
            .set_ex(&key, user_id, ttl_seconds as u64)
            .await?;
        self.client.sadd(&index_key, jti).await?;
        self.client.expire(&index_key, ttl_seconds).await?;
        Ok(())
    }

    /// Atomically rotate a refresh token: consume the old JTI and store the new one
    /// in a single Lua script (one Redis round-trip, no crash window between the two).
    ///
    /// Returns `Some(user_id)` on success, `None` if the old token was not found
    /// (already consumed or revoked).  The reverse index (`user_tokens:{user_id}`) is
    /// updated within the same script so logout-all always sees the current token.
    pub(crate) async fn rotate_refresh_token(
        &mut self,
        old_jti: &str,
        new_jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<Option<String>> {
        let old_key = format!("refresh_token:{}", old_jti);
        let new_key = format!("refresh_token:{}", new_jti);
        let index_key = format!("user_tokens:{}", user_id);

        // Lua script:
        // 1. GET the old token — if absent, return nil (already consumed).
        // 2. DEL old token.
        // 3. SET new token with TTL.
        // 4. SADD + EXPIRE on the per-user reverse index.
        // All operations are serialised by Redis's single-threaded command executor.
        let script = redis::Script::new(
            r#"
            local val = redis.call('GET', KEYS[1])
            if not val then
                return false
            end
            redis.call('DEL', KEYS[1])
            redis.call('SETEX', KEYS[2], ARGV[1], ARGV[2])
            redis.call('SADD',  KEYS[3], ARGV[3])
            redis.call('EXPIRE', KEYS[3], ARGV[1])
            return val
            "#,
        );

        let result: redis::Value = script
            .key(&old_key)
            .key(&new_key)
            .key(&index_key)
            .arg(ttl_seconds)
            .arg(user_id)
            .arg(new_jti)
            .invoke_async(self.client.connection_mut())
            .await?;

        match result {
            redis::Value::BulkString(bytes) => {
                Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
            }
            _ => Ok(None),
        }
    }

    /// Revoke all refresh tokens for a user (logout from all devices).
    /// Uses the per-user reverse index user_tokens:{user_id} (populated by store_refresh_token)
    /// to avoid a KEYS scan which blocks the Redis event loop.
    pub(crate) async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        let index_key = format!("user_tokens:{}", user_id);

        let jtis: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&index_key)
            .query_async(self.client.connection_mut())
            .await
            .unwrap_or_default();

        let mut deleted_count = 0usize;
        for jti in &jtis {
            let token_key = format!("refresh_token:{}", jti);
            let n: i64 = self.client.del(&token_key).await.unwrap_or(0);
            deleted_count += n as usize;
        }
        self.client.del(&index_key).await.unwrap_or(0i64);

        tracing::info!(
            user_id = %user_id,
            deleted_count = deleted_count,
            "Revoked all refresh tokens for user"
        );

        Ok(())
    }

    /// Store invalidated access token (for soft logout)
    ///
    /// Stores token JTI with short TTL to prevent reuse after logout
    /// TTL should match access token lifetime
    pub(crate) async fn invalidate_access_token(
        &mut self,
        jti: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = invalidated_token_key(jti);
        let _: () = self.client.set_ex(&key, "1", ttl_seconds as u64).await?;
        Ok(())
    }

    /// Check if access token is invalidated (was revoked)
    ///
    /// # Returns
    /// * `Ok(true)` - Token is invalidated (should be rejected)
    /// * `Ok(false)` - Token is valid (not invalidated)
    pub(crate) async fn is_token_invalidated(&mut self, jti: &str) -> Result<bool> {
        let key = invalidated_token_key(jti);
        let exists: bool = self.client.exists(&key).await?;
        Ok(exists)
    }

    /// Mark a device as revoked so any access token carrying that `device_id`
    /// claim is rejected until TTL expires (should match max access-token lifetime).
    ///
    /// Complements JTI blocklist: we do not have a per-device access-token index,
    /// so a single Redis key covers all outstanding tokens for the device.
    pub(crate) async fn mark_device_revoked(
        &mut self,
        device_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = revoked_device_key(device_id);
        let ttl = ttl_seconds.max(1) as u64;
        let _: () = self.client.set_ex(&key, "1", ttl).await?;
        tracing::info!(device_id = %device_id, ttl_seconds = ttl, "Marked device revoked");
        Ok(())
    }

    /// Returns true if the device was revoked via [`mark_device_revoked`].
    pub(crate) async fn is_device_revoked(&mut self, device_id: &str) -> Result<bool> {
        let key = revoked_device_key(device_id);
        let exists: bool = self.client.exists(&key).await?;
        Ok(exists)
    }

    // =========================================================================
    // Device Link Tokens (for multi-device QR linking)
    // =========================================================================

    /// Store a device link token with 15-minute TTL.
    /// Value: "{user_id}" — the user who initiated the link.
    pub(crate) async fn store_device_link_token(
        &mut self,
        token: &str,
        user_id: &str,
    ) -> Result<()> {
        let key = format!("device_link:{}", token);
        let _: () = self.client.set_ex(&key, user_id, 15 * 60).await?;
        Ok(())
    }

    /// Consume a device link token (one-time use): returns the user_id if valid.
    /// Deletes the token atomically so it cannot be reused.
    pub(crate) async fn consume_device_link_token(
        &mut self,
        token: &str,
    ) -> Result<Option<String>> {
        let key = format!("device_link:{}", token);
        // A process-local mutex does not serialize consumers on other replicas.
        Ok(redis::cmd("GETDEL")
            .arg(&key)
            .query_async(self.client.connection_mut())
            .await?)
    }

    /// Whether a device link token is still unused, and for whom: the user_id, without
    /// consuming it.
    pub(crate) async fn peek_device_link_token(&mut self, token: &str) -> Result<Option<String>> {
        let key = format!("device_link:{}", token);
        Ok(self.client.get(&key).await?)
    }

    /// Record which device used a link token and the proof of keys it presented, for the
    /// account that issued the token to read (`GetDeviceLinkResult`). Same 15-minute life as
    /// the token. Value: `len(user_id) u8 ‖ user_id ‖ len(device_id) u8 ‖ device_id ‖ proof`.
    pub(crate) async fn store_device_link_result(
        &mut self,
        token: &str,
        user_id: &str,
        device_id: &str,
        proof: &[u8],
    ) -> Result<()> {
        let key = format!("device_link_result:{}", token);
        let value = encode_link_result(user_id, device_id, proof)?;
        let _: () = self.client.set_ex(&key, value, 15 * 60).await?;
        Ok(())
    }

    /// The result stored by [`store_device_link_result`]: `(user_id, device_id, proof)`.
    pub(crate) async fn get_device_link_result(
        &mut self,
        token: &str,
    ) -> Result<Option<(String, String, Vec<u8>)>> {
        let key = format!("device_link_result:{}", token);
        let value: Option<Vec<u8>> = self.client.get(&key).await?;
        Ok(value.and_then(|v| decode_link_result(&v)))
    }

    // =========================================================================
    // Join Request Tokens (Flow B: TUI → Phone linking)
    // =========================================================================

    /// Store a join request payload with 10-minute TTL.
    ///
    /// The payload is opaque bytes: it carries X25519/Ed25519 key material, so the
    /// caller serializes it in a binary format rather than base64-in-JSON.
    pub(crate) async fn store_join_request(
        &mut self,
        pending_device_id: &str,
        payload: &[u8],
    ) -> Result<()> {
        let key = format!("join_req:{}", pending_device_id);
        let _: () = self.client.set_ex(&key, payload, 10 * 60).await?;
        Ok(())
    }

    /// Get a join request payload by pending_device_id (non-destructive read).
    pub(crate) async fn get_join_request(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let key = format!("join_req:{}", pending_device_id);
        let payload: Option<Vec<u8>> = self.client.get(&key).await?;
        Ok(payload)
    }

    /// Atomically consume a join request (GETDEL).
    /// Returns the payload if it existed.
    pub(crate) async fn consume_join_request(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let key = format!("join_req:{}", pending_device_id);
        // A process-local mutex does not serialize consumers on other replicas.
        Ok(redis::cmd("GETDEL")
            .arg(&key)
            .query_async(self.client.connection_mut())
            .await?)
    }

    /// Store approved join result with tokens, 2-minute TTL.
    /// Value format: "{access_token}:{refresh_token}:{user_id}:{exp_timestamp}"
    pub(crate) async fn store_join_approved(
        &mut self,
        pending_device_id: &str,
        value: &str,
    ) -> Result<()> {
        let key = format!("join_approved:{}", pending_device_id);
        let _: () = self.client.set_ex(&key, value, 2 * 60).await?;
        Ok(())
    }

    /// Get approved join result by pending_device_id.
    /// Returns: "{access_token}:{refresh_token}:{user_id}:{exp_timestamp}" or None.
    pub(crate) async fn get_join_approved(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<String>> {
        let key = format!("join_approved:{}", pending_device_id);
        let value: Option<String> = self.client.get(&key).await?;
        Ok(value)
    }
}

fn encode_link_result(user_id: &str, device_id: &str, proof: &[u8]) -> Result<Vec<u8>> {
    let (u, d) = (user_id.as_bytes(), device_id.as_bytes());
    let (Ok(ul), Ok(dl)) = (u8::try_from(u.len()), u8::try_from(d.len())) else {
        anyhow::bail!("link result ids over 255 bytes");
    };
    let mut out = Vec::with_capacity(2 + u.len() + d.len() + proof.len());
    out.push(ul);
    out.extend_from_slice(u);
    out.push(dl);
    out.extend_from_slice(d);
    out.extend_from_slice(proof);
    Ok(out)
}

fn decode_link_result(v: &[u8]) -> Option<(String, String, Vec<u8>)> {
    let ul = *v.first()? as usize;
    let user = std::str::from_utf8(v.get(1..1 + ul)?).ok()?.to_string();
    let rest = v.get(1 + ul..)?;
    let dl = *rest.first()? as usize;
    let device = std::str::from_utf8(rest.get(1..1 + dl)?).ok()?.to_string();
    let proof = rest.get(1 + dl..)?.to_vec();
    Some((user, device, proof))
}

#[cfg(test)]
mod link_result_tests {
    use super::*;

    #[test]
    fn link_result_round_trips() {
        let enc = encode_link_result("14f28d31-0000-4000-8000-000000000001", "6f5e37ac", &[9; 32])
            .unwrap();
        assert_eq!(
            decode_link_result(&enc),
            Some((
                "14f28d31-0000-4000-8000-000000000001".to_string(),
                "6f5e37ac".to_string(),
                vec![9; 32]
            ))
        );
        // An empty proof (a client older than device certificates) is a result, not an error.
        let enc = encode_link_result("u", "d", &[]).unwrap();
        assert_eq!(
            decode_link_result(&enc),
            Some(("u".to_string(), "d".to_string(), vec![]))
        );
        assert_eq!(decode_link_result(&enc[..2]), None);
    }
}

#[cfg(test)]
mod blocklist_standing_tests {
    use super::*;

    /// The key spellings are a contract with every writer and every other reader: identity writes
    /// `invalidated_token:{jti}` on logout, and the services that check without messaging
    /// (`construct_server_shared::revocation`) read it by the same name.
    #[test]
    fn the_key_spellings_are_unchanged() {
        assert_eq!(invalidated_token_key("jti-1"), "invalidated_token:jti-1");
        assert_eq!(revoked_device_key("dev-1"), "revoked_device:dev-1");
    }

    /// `nil` is absent and anything else is present — the same answer `EXISTS` gave, including for
    /// a key that exists holding nothing.
    #[test]
    fn a_nil_slot_is_absent_and_a_present_slot_is_set() {
        assert_eq!(
            standing_from_reply(true, &[None, None]),
            BlocklistStanding::default()
        );
        assert_eq!(
            standing_from_reply(true, &[Some("1".into()), None]),
            BlocklistStanding {
                token_invalidated: true,
                device_revoked: false
            }
        );
        assert_eq!(
            standing_from_reply(true, &[None, Some("1".into())]),
            BlocklistStanding {
                token_invalidated: false,
                device_revoked: true
            }
        );
        assert_eq!(
            standing_from_reply(true, &[Some("1".into()), Some(String::new())]),
            BlocklistStanding {
                token_invalidated: true,
                device_revoked: true
            },
            "an empty value is a key that exists, which is what EXISTS counted"
        );
    }

    /// A token that names no device sends one key, so its reply has one slot and nothing may read
    /// past it as a revoked device.
    #[test]
    fn a_device_less_read_cannot_report_a_revoked_device() {
        assert!(!standing_from_reply(false, &[None]).device_revoked);
        assert!(
            !standing_from_reply(true, &[None]).device_revoked,
            "a short reply is not a revoked device either"
        );
    }
}
