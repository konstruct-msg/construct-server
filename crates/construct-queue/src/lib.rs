//! Redis mailboxes, token/revocation state, PoW and active anti-abuse primitives.
//! Production delivery is stream fan-out followed by inbox wakeup; reads never delete
//! messages. MAXLEN and the seven-day age sweep own mailbox retention.

mod cursor;
mod dedup;
mod delivery;
mod gap;
mod intake_generation;
mod pow;
mod push_outstanding;
mod rate_limiting;
mod sessions;
mod tokens;

use cursor::StreamPosition;
pub use cursor::{InvalidMailboxCursor, MailboxCursor};
pub use dedup::{MessageDedupKey, is_message_duplicate};
pub use delivery::MailboxWrites;
pub use gap::MailboxGap;
pub use intake_generation::intake_generation_key;
pub use pow::PowChallengeRecord;
pub use push_outstanding::{PUSH_OUTSTANDING_TTL_SECONDS, push_outstanding_key};
pub use tokens::{
    BlocklistStanding, blocklist_standing, invalidated_token_key, revoked_device_key,
};

/// How long a message may sit in a mailbox: the hourly age sweep
/// (`trim_streams_by_age`) deletes anything older. Delivery deletes nothing —
/// retention is this sweep plus `MAXLEN ~` on XADD (construct-docs
/// `decisions/minimal-server-delivery.md`). The privacy policy states this number
/// and the landing's `check-claims.py` reads it from here.
///
/// Seven days, because that is what the clients are built for: the core
/// (construct-core `crypto::keys::QUEUE_TTL_SECS`) keeps a retired session's envelope pair
/// and a rotated signed prekey exactly long enough for a message written under them to
/// wait this long. A message older than that can still be fetched but no longer opened.
///
/// Until 2026-10-11 this was 30. It had been a literal in messaging-service while
/// `MESSAGE_TTL_DAYS=7` sat in every env file, read into config and used by nothing;
/// on 2026-10-05 the literal won and became this constant. The week was the intended
/// value all along, and the clients' key lifetimes were set against it.
pub const MAILBOX_MAX_AGE_DAYS: u64 = 7;

#[cfg(test)]
mod tests;

use anyhow::Result;
use construct_config::Config;
use construct_redis::RedisClient;
use std::sync::Arc;

/// Shared Redis state for the services. Messages are opaque MessagePack envelopes
/// in per-device/legacy-user streams; lifecycle and E2E meaning remain in the core.
// MessageQueue clones share the same underlying Redis multiplexed connection.
// Each clone is safe to use concurrently from a separate Tokio task without
// additional locking, because redis::aio::ConnectionManager pipelines commands
// internally. This allows per-stream queue clones to call XREAD in parallel
// without serializing on a shared Mutex.
#[derive(Clone)]
pub struct MessageQueue {
    client: RedisClient,
    delivery_queue_prefix: Arc<str>,
    /// Immutable boot-time snapshot, shared by per-stream queue handles rather than deep-cloned.
    config: Arc<Config>,
}

impl MessageQueue {
    pub async fn new(config: &Config) -> Result<Self> {
        tracing::debug!("Connecting to Redis via construct-redis...");

        // Parse Redis URL to check if TLS is required
        let is_tls = config.redis_url.starts_with("rediss://");
        if is_tls {
            tracing::info!("Redis TLS enabled (rediss://)");
        } else {
            tracing::info!("Redis TLS not enabled (redis://)");
        }

        // Use RedisClient from construct-redis
        let client = RedisClient::connect(&config.redis_url)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

        tracing::info!("Mailbox retention: {} days", MAILBOX_MAX_AGE_DAYS);
        Ok(Self {
            client,
            delivery_queue_prefix: Arc::from(config.delivery_queue_prefix.as_str()),
            config: Arc::new(config.clone()),
        })
    }

    // ============================================================================
    // Residual legacy-session cleanup (used by device deactivation)
    // ============================================================================

    pub async fn revoke_all_sessions(&mut self, user_id: &str) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .revoke_all_sessions(user_id)
            .await
    }

    // ============================================================================
    // Rate Limiting (delegated to rate_limiting module)
    // ============================================================================

    /// How many Privacy Pass tokens this user has already been issued in the
    /// current UTC hour. Missing key is zero, not an error.
    pub async fn token_issuance_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .token_issuance_count(user_id)
            .await
    }

    /// Reserve exactly `grant` tokens if `grant` still fits under `cap`.
    ///
    /// Returns the grant on success and `0` when a concurrent issuer took the
    /// room between the caller's read and this compare-and-swap. Never increments
    /// past the cap: the previous counter moved by the whole request and the
    /// refusal came afterwards, which burned the remainder of the hour.
    pub async fn try_reserve_token_issuance(
        &mut self,
        user_id: &str,
        grant: u32,
        cap: u32,
    ) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .try_reserve_token_issuance(user_id, grant, cap)
            .await
    }

    pub async fn increment_rate_limit(&mut self, key: &str, ttl_seconds: i64) -> Result<i64> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_rate_limit(key, ttl_seconds)
            .await
    }

    pub async fn increment_failed_login_count(&mut self, username: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_failed_login_count(username)
            .await
    }

    pub async fn reset_failed_login_count(&mut self, username: &str) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .reset_failed_login_count(username)
            .await
    }

    pub async fn block_user_temporarily(
        &mut self,
        user_id: &str,
        duration_seconds: i64,
        reason: &str,
    ) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .block_user_temporarily(user_id, duration_seconds, reason)
            .await
    }

    pub async fn is_user_blocked(&mut self, user_id: &str) -> Result<Option<String>> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .is_user_blocked(user_id)
            .await
    }

    // ============================================================================
    // Token Management (delegated to tokens module)
    // ============================================================================

    pub async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_refresh_token(jti, user_id, ttl_seconds)
            .await
    }

    /// Atomically rotate refresh token: consume old JTI and store new JTI in one
    /// Redis Lua script.  Eliminates the crash window between consume and store.
    /// Returns Some(user_id) on success, None if old token not found (already used).
    pub async fn rotate_refresh_token(
        &mut self,
        old_jti: &str,
        new_jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .rotate_refresh_token(old_jti, new_jti, user_id, ttl_seconds)
            .await
    }

    pub async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .revoke_all_user_tokens(user_id)
            .await
    }

    pub async fn invalidate_access_token(&mut self, jti: &str, ttl_seconds: i64) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .invalidate_access_token(jti, ttl_seconds)
            .await
    }

    pub async fn is_token_invalidated(&mut self, jti: &str) -> Result<bool> {
        tokens::TokenManager::new(&mut self.client)
            .is_token_invalidated(jti)
            .await
    }

    pub async fn mark_device_revoked(&mut self, device_id: &str, ttl_seconds: i64) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .mark_device_revoked(device_id, ttl_seconds)
            .await
    }

    pub async fn is_device_revoked(&mut self, device_id: &str) -> Result<bool> {
        tokens::TokenManager::new(&mut self.client)
            .is_device_revoked(device_id)
            .await
    }

    // =========================================================================
    // Device Link Tokens
    // =========================================================================

    pub async fn store_device_link_token(&mut self, token: &str, user_id: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_device_link_token(token, user_id)
            .await
    }

    pub async fn consume_device_link_token(&mut self, token: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .consume_device_link_token(token)
            .await
    }

    pub async fn peek_device_link_token(&mut self, token: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .peek_device_link_token(token)
            .await
    }

    pub async fn store_device_link_result(
        &mut self,
        token: &str,
        user_id: &str,
        device_id: &str,
        proof: &[u8],
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_device_link_result(token, user_id, device_id, proof)
            .await
    }

    pub async fn get_device_link_result(
        &mut self,
        token: &str,
    ) -> Result<Option<(String, String, Vec<u8>)>> {
        tokens::TokenManager::new(&mut self.client)
            .get_device_link_result(token)
            .await
    }

    // =========================================================================
    // Join Request Tokens (Flow B)
    // =========================================================================

    pub async fn store_join_request(
        &mut self,
        pending_device_id: &str,
        payload: &[u8],
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_join_request(pending_device_id, payload)
            .await
    }

    pub async fn get_join_request(&mut self, pending_device_id: &str) -> Result<Option<Vec<u8>>> {
        tokens::TokenManager::new(&mut self.client)
            .get_join_request(pending_device_id)
            .await
    }

    pub async fn consume_join_request(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        tokens::TokenManager::new(&mut self.client)
            .consume_join_request(pending_device_id)
            .await
    }

    pub async fn store_join_approved(
        &mut self,
        pending_device_id: &str,
        value: &str,
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_join_approved(pending_device_id, value)
            .await
    }

    pub async fn get_join_approved(&mut self, pending_device_id: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .get_join_approved(pending_device_id)
            .await
    }

    // ============================================================================
    // Basic Operations
    // ============================================================================

    pub async fn ping(&mut self) -> Result<()> {
        let _: () = redis::cmd("PING")
            .query_async(self.client.connection_mut())
            .await?;
        Ok(())
    }

    /// Get a string value by key
    pub async fn get(&mut self, key: &str) -> Result<Option<String>> {
        use redis::AsyncCommands;
        let value: Option<String> = self.client.connection_mut().get(key).await?;
        Ok(value)
    }

    /// Record that a message push is now outstanding for `device_id`. Returns `true` when this
    /// call set the marker (no push was outstanding: send), `false` when one already was (skip).
    /// One atomic `SET NX EX`, so two envelopes racing for the same device cannot both send.
    pub async fn try_mark_push_outstanding(&mut self, device_id: &str) -> Result<bool> {
        let set: Option<String> = redis::cmd("SET")
            .arg(push_outstanding_key(device_id))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(PUSH_OUTSTANDING_TTL_SECONDS)
            .query_async(self.client.connection_mut())
            .await?;
        Ok(set.is_some())
    }

    /// The device read its mailbox, or the push could not be sent: forget the marker.
    pub async fn clear_push_outstanding(&mut self, device_id: &str) -> Result<()> {
        self.delete(&push_outstanding_key(device_id)).await
    }

    /// Delete a key
    pub async fn delete(&mut self, key: &str) -> Result<()> {
        use redis::AsyncCommands;
        let _: i64 = self.client.connection_mut().del(key).await?;
        Ok(())
    }

    // ============================================================================
    // Message Delivery (delegated to delivery module)
    // ============================================================================

    async fn read_user_messages_from_stream(
        &mut self,
        user_id: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .read_user_messages_from_stream(user_id, since_id, count)
            .await
    }

    // `trim_offline_stream` was removed with minimal-server-delivery step 2 — see the
    // note at its old site in delivery.rs. Nothing may delete a user's mail from a
    // cursor the user's client supplied.

    pub async fn track_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<()> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .track_user_online(user_id, server_instance_id)
            .await
    }

    pub async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .untrack_user_online(user_id)
            .await
    }

    pub async fn get_user_server_instance(&mut self, user_id: &str) -> Result<Option<String>> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .get_user_server_instance(user_id)
            .await
    }

    /// Fan-out a message to per-device Redis streams (multi-device support).
    ///
    /// Writes to `{prefix}:offline:{user_id}:{device_id}` for each `device_id` in the slice.
    /// Also keeps the legacy user-level stream (`{prefix}:offline:{user_id}`) so old clients
    /// that don't send `x-device-id` continue to receive messages unchanged.
    ///
    /// The single `inbox:wakeup:{user_id}` wakeup publish is sufficient — all connected
    /// devices for a user subscribe to the same channel and wake up together.
    ///
    /// **Errors when the message reached no stream at all.** After the step-4 cutover
    /// (`MSG_MAILBOX_USER_WRITE=0`) the device streams are the only mailbox, and
    /// `device_ids` is empty whenever the device lookup failed — `fetch_recipient_device_ids_for_user`
    /// returns `vec![]` on a DB error and on an unparseable user id alike. Returning `Ok`
    /// there would let `dispatch_envelope` report a delivered message that was never
    /// written: the same silent loss the cursor trim was removed to prevent, re-entered
    /// from the write side. A hard error surfaces it to the sender instead.
    pub async fn write_message_to_device_streams(
        &mut self,
        user_id: &str,
        device_ids: &[String],
        envelope: &construct_message::types::MessageEnvelope,
    ) -> Result<delivery::MailboxWrites> {
        let write_user = self.config.messaging.mailbox_user_write;

        let writes = delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            &self.delivery_queue_prefix,
        )
        .write_message_to_mailboxes(user_id, device_ids, write_user, envelope)
        .await?;

        // A failed legacy write fails the send, as it always has: while
        // `MSG_MAILBOX_USER_WRITE` is on the user stream is the copy the dual-read still leans
        // on, and the caller must not be told the message was accepted. `mark_message_dispatched`
        // runs only after this returns `Ok`, so a retry is not a no-op.
        if writes.user_stream == Some(false) {
            anyhow::bail!("Failed to write the message to the user stream of recipient {user_id}");
        }

        // The "nowhere to land" check, in one place. Covers both shapes at once: no devices known
        // (a failed lookup and a user with none are indistinguishable here) and every device write
        // refused by Redis.
        if !write_user && writes.device_streams == 0 {
            anyhow::bail!(
                "No mailbox to write: user-stream writes are disabled (MSG_MAILBOX_USER_WRITE=0) \
                 and none of the {} device stream writes for recipient {user_id} landed",
                device_ids.len()
            );
        }

        Ok(writes)
    }

    /// Whether legacy user-stream XADD is enabled (`MSG_MAILBOX_USER_WRITE`).
    pub fn mailbox_user_write_enabled(&self) -> bool {
        self.config.messaging.mailbox_user_write
    }

    /// Read the recipient mailbox for delivery.
    ///
    /// - No `device_id`: legacy user stream only.
    /// - With `device_id` (step 3 transitional dual-read): merge device stream + user
    ///   stream, dedupe by `MessageDedupKey` (prefer device copy), order by Redis stream id
    ///   as a time watermark, return at most `count` entries.
    ///
    /// IDs are unique only within a source. Opaque cursors carry both exclusive offsets;
    /// legacy numeric callers may still pass separate `since_id` / `user_since_id` offsets.
    /// A complete opaque `since_id` is authoritative and needs no separate user position.
    /// `$` is resolved once to explicit source tails before reading. No cursor trims data.
    pub async fn read_mailbox_messages(
        &mut self,
        user_id: &str,
        device_id: Option<&str>,
        since_id: Option<&str>,
        user_since_id: Option<&str>,
        count: usize,
    ) -> Result<MailboxPage> {
        let device_id = device_id.filter(|d| !d.is_empty());
        let (start, device_start, user_start) = self
            .mailbox_read_offsets(user_id, device_id, since_id, user_since_id)
            .await?;
        let Some(device_id) = device_id else {
            // Redis COUNT 0 means unbounded, not zero. Probe one row for a zero-limit
            // request but return/consume none; this also keeps the legacy path's maximum strict.
            let mut entries = self
                .read_user_messages_from_stream(user_id, Some(&user_start), count.max(1))
                .await?;
            let has_more = !entries.is_empty() && entries.len() >= count;
            entries.truncate(count);
            let mut resume = start;
            let mut entry_cursors = Vec::with_capacity(entries.len());
            for (id, _) in &entries {
                resume.user = resume.user.max(id.parse()?);
                entry_cursors.push(resume);
            }
            return Ok(MailboxPage {
                entries,
                user_only_ids: Vec::new(),
                sibling_skipped: 0,
                has_more,
                resume,
                entry_cursors,
            });
        };

        // Oversample each source so the merge can still fill `count` after dedupe.
        let per_source = count.saturating_mul(2).max(1);
        let (device_msgs, user_msgs) = delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            &self.delivery_queue_prefix,
        )
        .read_mailbox_streams(
            user_id,
            device_id,
            Some(&device_start),
            Some(&user_start),
            per_source,
        )
        .await?;

        merge_mailbox_pages(device_msgs, user_msgs, count, per_source, device_id, start)
    }

    /// Resolve a complete token (or the two legacy offsets) without repeatedly interpreting `$`
    /// as a moving tail. Kept separate from XREAD so the resulting page owns its exact start.
    async fn mailbox_read_offsets<'a>(
        &mut self,
        user_id: &str,
        device_id: Option<&str>,
        since: Option<&'a str>,
        user_since: Option<&'a str>,
    ) -> Result<(
        MailboxCursor,
        std::borrow::Cow<'a, str>,
        std::borrow::Cow<'a, str>,
    )> {
        use std::borrow::Cow;
        if let Some(raw) = since.filter(|s| s.starts_with("mc")) {
            let cursor: MailboxCursor = raw.parse()?;
            return Ok((
                cursor,
                Cow::Owned(cursor.device.to_string()),
                Cow::Owned(cursor.user.to_string()),
            ));
        }
        let user_key = format!("{}:offline:{user_id}", self.delivery_queue_prefix);
        let device_key = device_id.map(|d| format!("{user_key}:{d}"));
        let mut device = delivery::DeliveryManager::stream_start_id(
            device_key.as_deref().unwrap_or(&user_key),
            since,
        );
        let mut user = delivery::DeliveryManager::stream_start_id(
            &user_key,
            if device_id.is_some() {
                user_since
            } else {
                since
            },
        );
        // There is no device source for a legacy device-less `$` request.
        if device_id.is_none() && device == "$" {
            device = Cow::Borrowed("0");
        }
        let tails = [
            (device == "$").then(|| {
                (
                    true,
                    device_key
                        .as_deref()
                        .expect("a device tail has a device key"),
                )
            }),
            (user == "$").then_some((false, user_key.as_str())),
        ];
        let tail_count = tails.iter().flatten().count();
        if tail_count > 0 {
            let mut pipe = redis::Pipeline::with_capacity(tail_count);
            pipe.ignore_errors();
            for (_, key) in tails.iter().flatten() {
                pipe.cmd("XINFO").arg("STREAM").arg(key);
            }
            let replies: Vec<redis::Value> = pipe.query_async(self.client.connection_mut()).await?;
            anyhow::ensure!(replies.len() == tail_count, "incomplete mailbox tail reply");
            for ((on_device, _), reply) in tails.into_iter().flatten().zip(replies) {
                let position = match reply {
                    redis::Value::ServerError(e) => {
                        let text = e.to_string();
                        anyhow::ensure!(
                            text.contains("no such key") || text.contains("WRONGTYPE"),
                            "failed to resolve mailbox tail: {text}"
                        );
                        "0-0".to_string()
                    }
                    info => gap::parse_xinfo_stream(&info)
                        .last_generated
                        .ok_or_else(|| anyhow::anyhow!("missing mailbox tail position"))?,
                };
                if on_device {
                    device = Cow::Owned(position);
                } else {
                    user = Cow::Owned(position);
                }
            }
        }
        let cursor = MailboxCursor {
            device: device.parse()?,
            user: user.parse()?,
        };
        Ok((cursor, device, user))
    }

    /// Whether the mailbox read from `since` lost entries after it — the device's stream first,
    /// then the user stream both are merged from (`read_mailbox_messages`). A missing stream is no
    /// gap: nothing was ever written to it, or it went with the account.
    pub async fn mailbox_gap(
        &mut self,
        user_id: &str,
        device_id: Option<&str>,
        since: &str,
    ) -> Result<Option<MailboxGap>> {
        let Ok(cursor) = since.parse::<MailboxCursor>() else {
            return Ok(None); // `$` and unrecognized legacy bookmarks name no past interval.
        };
        let prefix = &self.delivery_queue_prefix;
        let mut keys = Vec::new();
        if let Some(device) = device_id.filter(|d| !d.is_empty()) {
            keys.push((
                format!("{prefix}:offline:{user_id}:{device}"),
                cursor.device,
            ));
        }
        keys.push((format!("{prefix}:offline:{user_id}"), cursor.user));
        for (key, position) in keys {
            let reply: redis::RedisResult<redis::Value> = redis::cmd("XINFO")
                .arg("STREAM")
                .arg(&key)
                .query_async(self.client.connection_mut())
                .await;
            match reply {
                Ok(info) => {
                    let stream = gap::parse_xinfo_stream(&info);
                    let cap = self.config.messaging.queue_maxlen_standard.max(1) as u64;
                    if let Some(found) = gap::mailbox_gap(&position.to_string(), &stream, cap) {
                        return Ok(Some(found));
                    }
                }
                Err(e) if e.to_string().to_lowercase().contains("no such key") => continue,
                Err(e) => return Err(anyhow::Error::new(e).context("XINFO STREAM failed")),
            }
        }
        Ok(None)
    }

    /// Returns true if this scoped delivery was already dispatched (duplicate retry).
    pub async fn is_message_duplicate(&mut self, key: &MessageDedupKey) -> Result<bool> {
        is_message_duplicate(self.client.connection_mut(), key).await
    }

    /// Mark a scoped delivery as dispatched (idempotency key, TTL 24h).
    pub async fn mark_message_dispatched(&mut self, key: &MessageDedupKey) -> Result<()> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .mark_message_dispatched(key)
            .await
    }

    /// Clone the internal Redis ConnectionManager for rate-limiting / caching operations.
    ///
    /// `ConnectionManager` is designed to be cloned — the clone shares the same underlying
    /// connection pool and reconnect logic. Callers get an independent handle without
    /// needing to hold the queue lock while performing Redis operations.
    pub fn clone_redis_connection(&self) -> redis::aio::ConnectionManager {
        self.client.connection().clone()
    }

    /// Trim all offline message streams to remove entries older than `max_age_seconds`.
    ///
    /// Delegates to `DeliveryManager::trim_streams_by_age`. Intended to be called from
    /// a periodic background task (every hour) to enforce `MAILBOX_MAX_AGE_DAYS`.
    pub async fn trim_streams_by_age(&mut self, max_age_seconds: u64) -> Result<u64> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .trim_streams_by_age(max_age_seconds)
            .await
    }

    /// Delete every mailbox of `user_id` — the user stream and each per-device
    /// stream — for account deletion. Returns how many streams existed.
    ///
    /// Without this a deleted account's queued messages stayed until the age sweep,
    /// up to `MAILBOX_MAX_AGE_DAYS`, though the account and its keys were gone.
    pub async fn delete_mailbox(&mut self, user_id: &str) -> Result<u64> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .delete_mailbox(user_id)
            .await
    }

    /// Forget the account's intake-key generation, for account deletion. The one place it
    /// is removed: it carries no TTL on purpose (`intake_generation_key`).
    pub async fn delete_intake_generation(&mut self, user_id: &str) -> Result<()> {
        let _: i64 = self.client.del(intake_generation_key(user_id)).await?;
        Ok(())
    }

    /// Purge all pending messages from `sender_id` out of `recipient_id`'s delivery
    /// streams (user-level and all per-device streams).
    ///
    /// Call immediately after a block operation to prevent the blocked contact's
    /// messages from being delivered on the next background fetch.
    /// Returns the number of stream entries deleted (informational only).
    pub async fn purge_stream_messages_from_sender(
        &mut self,
        recipient_id: &str,
        sender_id: &str,
    ) -> Result<u64> {
        delivery::DeliveryManager::new(&mut self.client, &self.config, &self.delivery_queue_prefix)
            .purge_messages_from_sender(recipient_id, sender_id)
            .await
    }
}

/// One mailbox read, plus the one number the step-4 cutover turns on.
pub struct MailboxPage {
    pub entries: Vec<(String, Option<construct_message::types::MessageEnvelope>)>,
    /// Entries in this page that the **device** stream did not have — they exist only
    /// because the legacy user stream is still written and still read.
    ///
    /// This is the cutover gate. Counting how many reads *used* dual-read says only that
    /// clients send a `device_id`; it cannot tell whether the device streams are complete,
    /// and completeness is the whole question before `MSG_MAILBOX_USER_WRITE=0` turns the
    /// user stream off. While this stays above zero, flipping the flag drops exactly these
    /// messages.
    ///
    /// **The ids, not a count.** A count above zero says the cutover is unsafe and nothing
    /// about why: the gate read 2 on 2026-09-21 and the only thing anyone could say about
    /// those two was the ten-minute window the scrape put them in. These are the messages
    /// the flag would have dropped, so they are what a reader needs to find the sender, the
    /// route and the reason. `user_only()` is the count, derived rather than carried
    /// alongside.
    pub user_only_ids: Vec<String>,
    /// User-stream entries named to **another** device of this account, left out of the
    /// page. They live in that device's stream by construction, so they are neither a
    /// delivery for this reader nor evidence about coverage — see `merge_mailbox_pages`.
    pub sibling_skipped: usize,
    /// Complete source positions after this page, including skipped sibling prefixes.
    resume: MailboxCursor,
    /// Complete positions after each entry, never the final page position on an early frame.
    entry_cursors: Vec<MailboxCursor>,
    /// The streams may hold more after this page: it was cut by `count`, or a source read came
    /// back full and the page stops at its last entry. Follows the reads, not `entries.len()`
    /// — a page stopped at a sibling-filled user read can be short, or empty, and still not
    /// be the end.
    pub has_more: bool,
}

impl MailboxPage {
    /// The next opaque cursor for a completed fetch/page. An empty page retains its start
    /// (or moves only over ignorable source prefixes); no cross-source maximum is taken.
    pub fn resume_cursor(&self) -> MailboxCursor {
        self.resume
    }

    /// Streaming consumes checkpoints alongside the corresponding envelopes. A failed send
    /// must not commit a later entry's checkpoint. Raw Redis IDs in `entries` are diagnostic only.
    ///
    /// # Panics
    /// If a caller changed the public entries' length: truncating the zip would silently drop
    /// ciphertext. Production builders always construct one checkpoint per entry.
    pub fn into_cursor_entries(
        self,
    ) -> impl Iterator<
        Item = (
            MailboxCursor,
            Option<construct_message::types::MessageEnvelope>,
        ),
    > {
        assert_eq!(
            self.entry_cursors.len(),
            self.entries.len(),
            "mailbox entries and checkpoints must stay aligned"
        );
        self.entry_cursors
            .into_iter()
            .zip(self.entries.into_iter().map(|(_, env)| env))
    }

    /// How many delivered entries the device stream did not have — the cutover gate, as a
    /// number. Derived from `user_only_ids` so the two cannot disagree.
    pub fn user_only(&self) -> usize {
        self.user_only_ids.len()
    }
}

/// Merge device + user mailbox pages for transitional dual-read.
///
/// Prefer the device copy within the same `MessageDedupKey` scope. Order by Redis stream id
/// (millisecond watermark). Corrupt/`None` envelopes keep their stream ids for
/// cursor advance and never collide with a decoded envelope.
///
/// **A user-stream entry named to a different device is not this reader's.** The
/// legacy user stream holds every envelope of the account, including the ones
/// `dispatch_envelope` routed to exactly one device by `recipient_device`. Read whole,
/// it handed each device the envelopes of its siblings too — the 2026-09-21 baseline
/// (construct-docs `sessions/2026-09-21-multidevice-baseline.md`) measured every
/// envelope of a two-device account arriving on both devices, each unsealing the
/// other's copy far enough to drop it — and it counted every one of them as
/// `user_only`, so the cutover gate could never reach zero for an account with two
/// devices. Such an entry is in the named device's own stream already; it is skipped
/// here and counted separately. An entry named to *this* device that the device
/// stream lacks is still `user_only`: that is the incompleteness the gate exists for.
/// An unnamed entry (a sender that predates `recipient_device`, or a server-generated
/// envelope) is for every device and is merged as before.
///
/// Preserve the existing earliest-full-read horizon for bounded chronological page ordering.
/// Unlike the old shared watermark, resumption uses independent consumed prefixes. IDs can tie
/// across sources, and a count boundary MUST NOT advance the source of an unreturned peer.
fn merge_mailbox_pages(
    device_msgs: Vec<(String, Option<construct_message::types::MessageEnvelope>)>,
    user_msgs: Vec<(String, Option<construct_message::types::MessageEnvelope>)>,
    count: usize,
    source_limit: usize,
    reader_device: &str,
    start: MailboxCursor,
) -> Result<MailboxPage> {
    use construct_message::types::MessageEnvelope;
    use std::collections::{HashMap, hash_map::Entry};

    struct Candidate {
        id: String,
        position: StreamPosition,
        envelope: Option<MessageEnvelope>,
        on_device: bool,
    }
    // Rows refer to stable candidate indices, not another hash/digest or a copy of ciphertext.
    // MAX names a sibling skip. Every other index is assigned once below.
    struct SourceRow {
        position: StreamPosition,
        candidate: usize,
    }
    // A sibling-only read must not reserve a page of large envelope slots it never uses.
    let admitted = device_msgs.len().saturating_add(
        user_msgs
            .iter()
            .filter(|(_, env)| {
                env.as_ref().is_none_or(|e| {
                    e.recipient_device
                        .as_deref()
                        .is_none_or(|d| d == reader_device)
                })
            })
            .count(),
    );
    let mut candidates: Vec<Option<Candidate>> = Vec::with_capacity(admitted);
    let mut by_scope = HashMap::with_capacity(admitted);
    let mut user_rows = Vec::with_capacity(user_msgs.len());
    let mut device_rows = Vec::with_capacity(device_msgs.len());
    let mut sibling_skipped = 0;
    let mut horizon: Option<StreamPosition> = None;
    for source in [&device_msgs, &user_msgs] {
        if source.len() >= source_limit
            && let Some((id, _)) = source.last()
        {
            let last = id.parse::<StreamPosition>()?;
            horizon = Some(horizon.map_or(last, |h| h.min(last)));
        }
    }
    // User first, then device overwrites: payload preference and dedup scope are unchanged.
    for (on_device, source) in [(false, user_msgs), (true, device_msgs)] {
        let rows = if on_device {
            &mut device_rows
        } else {
            &mut user_rows
        };
        for (id, envelope) in source {
            let position = id.parse::<StreamPosition>()?;
            if !on_device
                && envelope.as_ref().is_some_and(|env| {
                    env.recipient_device
                        .as_deref()
                        .is_some_and(|d| d != reader_device)
                })
            {
                sibling_skipped += 1;
                rows.push(SourceRow {
                    position,
                    candidate: usize::MAX,
                });
                continue;
            }
            let index = if let Some(env) = &envelope {
                match by_scope.entry(MessageDedupKey::scope_for_envelope(env)) {
                    Entry::Occupied(e) => *e.get(),
                    Entry::Vacant(e) => {
                        let index = candidates.len();
                        candidates.push(None);
                        e.insert(index);
                        index
                    }
                }
            } else {
                let index = candidates.len();
                candidates.push(None); // Corrupt entries have distinct identities.
                index
            };
            candidates[index] = Some(Candidate {
                id,
                position,
                envelope,
                on_device,
            });
            rows.push(SourceRow {
                position,
                candidate: index,
            });
        }
    }
    drop(by_scope); // Only the stable row indices are needed from here on.
    let candidate = |index: usize| {
        candidates[index]
            .as_ref()
            .expect("every row has a candidate")
    };
    let mut order: Vec<_> = (0..candidates.len())
        .filter(|&i| horizon.is_none_or(|h| candidate(i).position <= h))
        .collect();
    order.sort_by(|&a, &b| {
        candidate(a)
            .position
            .cmp(&candidate(b).position)
            .then(a.cmp(&b))
    });
    let cut_by_count = order.len() > count;
    order.truncate(count); // Strict API maximum, even when IDs tie across streams.
    let mut delivered_at = vec![usize::MAX; candidates.len()];
    for (rank, &index) in order.iter().enumerate() {
        delivered_at[index] = rank + 1;
    }
    let mut resume = start;
    let mut entry_cursors = Vec::with_capacity(order.len());
    let (mut device_through, mut user_through) = (0, 0);
    // Consume only a contiguous prefix in each source. Nonrepresentative copies may be
    // skipped now: the representative's actual (source, ID) still blocks its component
    // until delivered. This includes older retries in the SAME source, not only user twins.
    // Thus duplicate-filled horizons can progress without losing the unissued representative.
    for rank in 0..=order.len() {
        for (on_device, rows, through, position) in [
            (true, &device_rows, &mut device_through, &mut resume.device),
            (false, &user_rows, &mut user_through, &mut resume.user),
        ] {
            while let Some(row) = rows.get(*through) {
                let ready = row.candidate == usize::MAX || {
                    let c = candidate(row.candidate);
                    c.envelope.is_none()
                        || on_device != c.on_device
                        || row.position != c.position
                        || delivered_at[row.candidate] <= rank
                };
                if !ready {
                    break;
                }
                *position = (*position).max(row.position);
                *through += 1;
            }
        }
        if rank > 0 {
            entry_cursors.push(resume);
        }
    }
    let mut entries = Vec::with_capacity(order.len());
    let mut user_only_ids = Vec::new();
    for index in order {
        let c = candidates[index]
            .take()
            .expect("each candidate is selected once");
        if !c.on_device
            && let Some(env) = &c.envelope
        {
            user_only_ids.push(env.message_id.clone());
        }
        entries.push((c.id, c.envelope));
    }
    Ok(MailboxPage {
        entries,
        user_only_ids,
        sibling_skipped,
        resume,
        entry_cursors,
        has_more: cut_by_count || horizon.is_some(),
    })
}

#[cfg(test)]
mod mailbox_merge_tests {
    use super::*;
    use construct_message::types::{MessageEnvelope, MessageType};

    fn merge_mailbox_pages(
        device: Vec<(String, Option<MessageEnvelope>)>,
        user: Vec<(String, Option<MessageEnvelope>)>,
        count: usize,
        source_limit: usize,
        reader: &str,
    ) -> MailboxPage {
        super::merge_mailbox_pages(
            device,
            user,
            count,
            source_limit,
            reader,
            MailboxCursor::default(),
        )
        .unwrap()
    }

    fn env(id: &str) -> MessageEnvelope {
        MessageEnvelope {
            message_id: id.to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            timestamp: 1,
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: b"x".to_vec(),
            content_hash: "h".to_string(),
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner: None,
            max_queue_len: None,
            proto_content_type: None,
            recipient_device: None,
        }
    }

    #[test]
    fn merge_prefers_device_copy_and_orders_by_stream_id() {
        let user = vec![
            ("100-0".to_string(), Some(env("m1"))),
            ("300-0".to_string(), Some(env("m2"))),
        ];
        // Same m1 on device with a different stream id — device wins.
        let device = vec![
            ("150-0".to_string(), Some(env("m1"))),
            ("200-0".to_string(), Some(env("m3"))),
        ];
        let page = merge_mailbox_pages(device, user, 10, 100, "dev");
        let ids: Vec<_> = page
            .entries
            .iter()
            .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.as_str()))
            .collect();
        assert_eq!(ids, vec!["m1", "m3", "m2"]);
        // m1 kept the device stream id
        assert_eq!(page.entries[0].0, "150-0");
        // m2 exists only in the user stream — the device fan-out missed it.
        assert_eq!(page.user_only(), 1);
    }

    #[test]
    fn merge_does_not_hide_another_senders_message_with_the_same_id() {
        let alice = env("same-id");
        let mut eve = alice.clone();
        eve.sender_id = "eve".into();
        let page = merge_mailbox_pages(
            vec![("100-1".into(), Some(alice.clone()))],
            vec![("100-0".into(), Some(alice)), ("200-0".into(), Some(eve))],
            10,
            100,
            "dev",
        );
        let senders: Vec<_> = page
            .entries
            .iter()
            .map(|(_, env)| env.as_ref().unwrap().sender_id.as_str())
            .collect();
        assert_eq!(senders, ["alice", "eve"]);
        assert_eq!(page.entries[0].0, "100-1", "prefer Alice's device copy");
        assert_eq!(
            page.user_only(),
            1,
            "Eve's id matching Alice's is not device coverage"
        );
    }

    #[test]
    fn merge_respects_count_cap() {
        let user = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
            ("300-0".to_string(), Some(env("c"))),
        ];
        let page = merge_mailbox_pages(vec![], user, 2, 100, "dev");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].1.as_ref().unwrap().message_id, "a");
        assert_eq!(page.entries[1].1.as_ref().unwrap().message_id, "b");
    }

    /// The gate the cutover reads. Zero means every delivered entry was on the device
    /// stream, so switching the user stream off would have changed nothing — which is
    /// the only evidence that makes `MSG_MAILBOX_USER_WRITE=0` safe.
    #[test]
    fn full_device_coverage_reports_no_user_only_entries() {
        let user = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
        ];
        let device = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
        ];
        assert_eq!(
            merge_mailbox_pages(device, user, 10, 100, "dev").user_only(),
            0
        );
    }

    /// Entries dropped by the count cap are re-read on the next poll, so counting them
    /// as a coverage failure now would keep the gate permanently red on a deep backlog.
    ///
    /// Three delivered entries, one of them covered: the covered and uncovered counts
    /// differ, so the assertion distinguishes "missing from the device stream" from its
    /// inverse. With two entries they coincide and the test passes either way.
    #[test]
    fn user_only_counts_delivered_entries_not_the_truncated_tail() {
        let user = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
            ("300-0".to_string(), Some(env("c"))),
            ("400-0".to_string(), Some(env("d"))),
        ];
        let device = vec![("100-0".to_string(), Some(env("a")))];
        let page = merge_mailbox_pages(device, user, 3, 100, "dev");
        assert_eq!(page.entries.len(), 3);
        assert_eq!(
            page.user_only(),
            2,
            "delivered `b` and `c` count, `d` does not"
        );
    }

    /// The gate names the messages, not just how many. Two delivered entries the device
    /// stream lacks, and the page says **which** — that is what a reader needs to go from
    /// "the cutover is unsafe" to the sender, the route and the reason.
    ///
    /// Mutation: report the count and discard the ids — this reddens; the count assertion
    /// above it does not.
    #[test]
    fn user_only_ids_name_the_messages_the_cutover_would_drop() {
        let user = vec![
            ("100-0".to_string(), Some(env("covered"))),
            ("200-0".to_string(), Some(env("stranded-1"))),
            ("300-0".to_string(), Some(env("stranded-2"))),
        ];
        let device = vec![("100-0".to_string(), Some(env("covered")))];
        let page = merge_mailbox_pages(device, user, 10, 100, "dev");
        let mut named = page.user_only_ids.clone();
        named.sort();
        assert_eq!(
            named,
            vec!["stranded-1".to_string(), "stranded-2".to_string()]
        );
        assert_eq!(
            page.user_only(),
            named.len(),
            "the count is derived from them"
        );
    }

    fn env_for(id: &str, device: &str) -> MessageEnvelope {
        let mut e = env(id);
        e.recipient_device = Some(device.to_string());
        e
    }

    /// The 2026-09-21 baseline, as a table: an account with devices `a` and `b`, three
    /// envelopes named to `b`, one named to `a`, one unnamed. Reader `a` must get its own
    /// and the unnamed one, never `b`'s — and `b`'s must not count as coverage failures,
    /// which is what kept the cutover gate red on every two-device account.
    #[test]
    fn user_stream_entries_named_to_a_sibling_are_neither_delivered_nor_counted() {
        let user = vec![
            ("100-0".to_string(), Some(env_for("to-b-1", "b"))),
            ("200-0".to_string(), Some(env_for("to-a", "a"))),
            ("300-0".to_string(), Some(env_for("to-b-2", "b"))),
            ("400-0".to_string(), Some(env("unnamed"))),
            ("500-0".to_string(), Some(env_for("to-b-3", "b"))),
        ];
        let device = vec![
            ("200-0".to_string(), Some(env_for("to-a", "a"))),
            ("400-0".to_string(), Some(env("unnamed"))),
        ];
        let page = merge_mailbox_pages(device, user, 10, 100, "a");
        let ids: Vec<_> = page
            .entries
            .iter()
            .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.as_str()))
            .collect();
        assert_eq!(ids, vec!["to-a", "unnamed"]);
        assert_eq!(
            page.user_only(),
            0,
            "everything delivered was on the device stream"
        );
        assert_eq!(page.sibling_skipped, 3);
    }

    /// The filter must not hide the very thing the gate exists for: an entry named to
    /// *this* device that the device stream does not have is a coverage failure, and it
    /// is still delivered, from the user stream, so nothing is lost.
    #[test]
    fn entry_named_to_the_reader_but_missing_from_its_stream_is_still_user_only() {
        let user = vec![("100-0".to_string(), Some(env_for("to-a", "a")))];
        let page = merge_mailbox_pages(vec![], user, 10, 100, "a");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.user_only(), 1);
        assert_eq!(page.sibling_skipped, 0);
    }

    /// The reader has nothing of its own; the user stream holds only a sibling's entries.
    /// Nothing is delivered, so the delivery cursor cannot move — but the user stream was
    /// examined through its last entry, and the caller is told so. Without this the same
    /// entries are read, decoded and counted on every poll until the reader's next message.
    #[test]
    fn a_page_of_only_sibling_entries_is_examined_through_its_last_id() {
        let user = vec![
            ("100-0".to_string(), Some(env_for("to-b-1", "b"))),
            ("200-0".to_string(), Some(env_for("to-b-2", "b"))),
        ];
        let page = merge_mailbox_pages(vec![], user, 10, 100, "a");
        assert!(page.entries.is_empty());
        assert_eq!(page.sibling_skipped, 2);
        assert_eq!(page.resume_cursor().user, StreamPosition(200, 0));
        assert_eq!(page.resume_cursor().device, StreamPosition(0, 0));
    }

    /// A cut page advances only the consumed user prefix, never the unseen suffix or
    /// the independent device component.
    #[test]
    fn a_page_cut_by_count_claims_only_the_consumed_user_prefix() {
        let user = vec![
            ("100-0".to_string(), Some(env("first"))),
            ("200-0".to_string(), Some(env("second"))),
            ("300-0".to_string(), Some(env_for("to-b", "b"))),
        ];
        let page = merge_mailbox_pages(vec![], user, 1, 100, "a");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.resume_cursor().user, StreamPosition(100, 0));
        assert_eq!(page.resume_cursor().device, StreamPosition(0, 0));
        assert!(page.has_more, "the cut entries are still to come");

        let nothing = merge_mailbox_pages(vec![], vec![], 10, 100, "a");
        assert_eq!(
            nothing.resume_cursor(),
            MailboxCursor::default(),
            "an empty user page examined nothing and moves nothing"
        );
        assert!(!nothing.has_more);
    }

    /// `unknown_device` fallback: the envelope names a device that was not in the active
    /// set, so `dispatch_envelope` wrote it to *every* device stream, name and all. The
    /// user-stream copy is skipped for a reader it does not name, but the device-stream
    /// copy still delivers — the fallback's whole point survives the filter.
    #[test]
    fn unknown_device_fallback_still_delivers_through_the_device_stream() {
        let user = vec![("100-0".to_string(), Some(env_for("m", "ghost")))];
        let device = vec![("100-0".to_string(), Some(env_for("m", "ghost")))];
        let page = merge_mailbox_pages(device, user, 10, 100, "a");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.user_only(), 0);
        assert_eq!(page.sibling_skipped, 1);
    }

    /// Stream IDs are unique only inside one source. Cutting between distinct messages with
    /// the same ID loses the unreturned peer on the next exclusive XREAD, regardless of sort order.
    #[test]
    fn a_page_boundary_must_not_split_a_shared_stream_id() {
        for count in [1, 2] {
            let device = vec![
                ("100-0".to_string(), Some(env("first"))),
                ("200-0".to_string(), Some(env("device-only"))),
            ];
            let user = vec![("200-0".to_string(), Some(env("user-only")))];
            let mut cursor = MailboxCursor::default();
            let mut received = Vec::new();
            let mut finished = false;
            for _ in 0..10 {
                let page = read_fixture(&device, &user, cursor, count, "dev");
                assert!(page.entries.len() <= count, "limit is a maximum");
                received.extend(ids(&page).into_iter().map(str::to_string));
                let next = page.resume_cursor();
                if !page.has_more {
                    finished = true;
                    break;
                }
                assert!(
                    next != cursor && next.join(cursor) == next,
                    "paging stalled or rewound a source"
                );
                cursor = next;
            }
            received.sort();
            received.dedup();
            assert!(finished);
            assert_eq!(
                received,
                ["device-only", "first", "user-only"],
                "count={count}: never skip an equal-ID peer"
            );
        }
    }

    /// Independent sequences in the same Redis millisecond can put a device copy before
    /// the current user horizon and its legacy twin on the next page. Delivery is
    /// at-least-once across pages, with scoped dedup *within* each merge. Fixed ids make
    /// this regression independent of Redis throughput and host clock granularity.
    #[test]
    fn paged_merge_preserves_every_message_with_independent_sequence_numbers() {
        let device = vec![
            ("1000-0".to_string(), Some(env_for("own", "a"))),
            ("1000-6".to_string(), Some(env_for("next", "a"))),
        ];
        let user = vec![
            ("1000-0".to_string(), Some(env_for("sibling-1", "b"))),
            ("1000-1".to_string(), Some(env_for("sibling-2", "b"))),
            ("1000-2".to_string(), Some(env_for("sibling-3", "b"))),
            ("1000-3".to_string(), Some(env_for("sibling-4", "b"))),
            ("1000-4".to_string(), Some(env("legacy-only"))),
            ("1000-5".to_string(), Some(env_for("own", "a"))),
        ];
        let mut cursor = MailboxCursor::default();
        let mut received = Vec::new();
        let mut complete = false;
        for _ in 0..10 {
            let page = read_fixture(&device, &user, cursor, 1, "a");
            received.extend(ids(&page).into_iter().map(str::to_string));
            let next = page.resume_cursor();
            if !page.has_more {
                complete = true;
                break;
            }
            assert!(
                next != cursor && next.join(cursor) == next,
                "paging stalled or rewound a source"
            );
            cursor = next;
        }
        assert!(complete, "paging must terminate");
        received.sort();
        received.dedup(); // Across pages: at-least-once; the client deduplicates message ids.
        assert_eq!(received, ["legacy-only", "next", "own"]);
    }

    #[test]
    fn same_source_retries_do_not_hold_a_prefix_behind_an_unissued_representative() {
        let source = vec![
            ("100-0".into(), Some(env("a"))),
            ("200-0".into(), Some(env("b"))),
            ("250-0".into(), Some(env("c"))),
            ("300-0".into(), Some(env("a"))),
        ];
        for device_source in [false, true] {
            let (device, user) = if device_source {
                (source.clone(), vec![])
            } else {
                (vec![], source.clone())
            };
            let first = read_fixture(&device, &user, MailboxCursor::default(), 2, "reader");
            assert_eq!(ids(&first), ["b", "c"]);
            let cursor = first.resume_cursor();
            assert_ne!(
                cursor,
                MailboxCursor::default(),
                "the old a is covered by the unissued a at 300"
            );
            let second = read_fixture(&device, &user, cursor, 2, "reader");
            assert_eq!(ids(&second), ["a"], "the representative was not skipped");
            assert!(!second.has_more);
        }
    }

    #[test]
    fn checkpoint_planning_moves_the_device_ciphertext_buffer_without_copying_it() {
        let mut chosen = env("same");
        chosen.encrypted_payload = vec![255; 32 * 1024];
        let pointer = chosen.encrypted_payload.as_ptr();
        let mut twin = env("same");
        twin.encrypted_payload = b"older user copy".to_vec();
        let page = merge_mailbox_pages(
            vec![("200-0".into(), Some(chosen))],
            vec![("100-0".into(), Some(twin))],
            1,
            2,
            "reader",
        );
        let output = page.entries[0].1.as_ref().unwrap();
        assert_eq!(output.encrypted_payload.len(), 32 * 1024);
        assert_eq!(output.encrypted_payload.as_ptr(), pointer);
        assert_eq!(page.user_only(), 0);
    }

    #[test]
    #[should_panic(expected = "mailbox entries and checkpoints must stay aligned")]
    fn a_caller_cannot_silently_zip_away_a_mailbox_entry() {
        let mut page = merge_mailbox_pages(
            vec![("100-0".into(), Some(env("a")))],
            vec![],
            1,
            2,
            "reader",
        );
        page.entries.clear(); // A programming error, not a malformed ciphertext or client cursor.
        let _ = page.into_cursor_entries();
    }

    /// All 15,625 short source layouts: absent/corrupt/a/b/sibling at three IDs in each
    /// stream, with retries, equal IDs and either horizon. Exercise full pages AND a fresh
    /// opaque-cursor reconnect after every first frame. This is the production merge.
    #[test]
    fn exhaustive_source_prefixes_survive_page_and_frame_boundaries() {
        use std::collections::BTreeSet;
        let mut checked = 0;
        for layout in 0..15_625 {
            let mut code = layout;
            let mut source = || {
                let mut rows = Vec::new();
                for id in 1..=3 {
                    let kind = code % 5;
                    code /= 5;
                    let env = match kind {
                        0 => continue,
                        1 => Some(env("a")),
                        2 => Some(env("b")),
                        3 => None,
                        _ => Some(env_for("sibling", "other")),
                    };
                    rows.push((format!("1000-{id}"), env));
                }
                rows
            };
            let device = source();
            let user = source();
            let expected: BTreeSet<_> = device
                .iter()
                .filter_map(|(_, e)| e.as_ref())
                .chain(
                    user.iter()
                        .filter_map(|(_, e)| e.as_ref())
                        .filter(|e| e.recipient_device.as_deref() != Some("other")),
                )
                .map(|e| e.message_id.clone())
                .collect();
            for count in [1, 2, 3] {
                for interrupt in [false, true] {
                    let mut cursor = MailboxCursor::default();
                    let mut received = BTreeSet::new();
                    let mut finished = false;
                    for _ in 0..32 {
                        let page = read_fixture(&device, &user, cursor, count, "reader");
                        assert!(page.entries.len() <= count, "strict limit, layout={layout}");
                        let end = page.resume_cursor();
                        let has_more = page.has_more;
                        let mut interrupted = false;
                        let mut next = end;
                        for (checkpoint, envelope) in page.into_cursor_entries() {
                            if let Some(env) = envelope {
                                received.insert(env.message_id);
                                if interrupt {
                                    next = checkpoint
                                        .to_string()
                                        .parse()
                                        .expect("client echoes opaque token");
                                    interrupted = true;
                                    break;
                                }
                            }
                        }
                        assert_eq!(
                            next.join(cursor),
                            next,
                            "no source rewinds, layout={layout}"
                        );
                        if !interrupted && !has_more {
                            finished = true;
                            break;
                        }
                        assert_ne!(
                            next, cursor,
                            "stalled layout={layout}, limit={count}, interrupt={interrupt}"
                        );
                        assert!(
                            next.to_string() > cursor.to_string(),
                            "legacy storage order"
                        );
                        cursor = next;
                    }
                    assert!(
                        finished,
                        "did not drain layout={layout}, limit={count}, interrupt={interrupt}"
                    );
                    assert_eq!(
                        received, expected,
                        "lost/leaked layout={layout}, limit={count}, interrupt={interrupt}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 93_750);
    }

    #[test]
    fn malformed_redis_ids_fail_the_read_instead_of_fabricating_a_checkpoint() {
        assert!(
            super::merge_mailbox_pages(
                vec![("bad-id".into(), Some(env("a")))],
                vec![],
                1,
                2,
                "reader",
                MailboxCursor::default()
            )
            .is_err()
        );
    }

    fn read_fixture(
        device: &[(String, Option<MessageEnvelope>)],
        user: &[(String, Option<MessageEnvelope>)],
        cursor: MailboxCursor,
        count: usize,
        reader: &str,
    ) -> MailboxPage {
        let read = |source: &[(String, Option<MessageEnvelope>)], offset: StreamPosition| {
            source
                .iter()
                .filter(|(id, _)| id.parse::<StreamPosition>().unwrap() > offset)
                .take(count * 2)
                .cloned()
                .collect()
        };
        super::merge_mailbox_pages(
            read(device, cursor.device),
            read(user, cursor.user),
            count,
            count * 2,
            reader,
            cursor,
        )
        .unwrap()
    }

    fn ids(page: &MailboxPage) -> Vec<&str> {
        page.entries
            .iter()
            .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.as_str()))
            .collect()
    }

    /// A three-device account: the user read is siblings' entries and comes back full at
    /// 300, while the reader's own stream reaches 400. The user stream may hold the reader's
    /// entries after 300 that this read never saw, so 400 waits: delivering it moved a
    /// one-cursor reader past them for good. Mutation: drop the `retain` — m2 is delivered
    /// and the cursor lands on 400.
    #[test]
    fn a_full_user_read_ends_the_page_at_its_last_entry() {
        let user = vec![
            ("100-0".to_string(), Some(env_for("to-b", "b"))),
            ("200-0".to_string(), Some(env_for("to-c", "c"))),
            ("300-0".to_string(), Some(env_for("to-b-2", "b"))),
        ];
        let device = vec![
            ("150-0".to_string(), Some(env_for("m1", "a"))),
            ("400-0".to_string(), Some(env_for("m2", "a"))),
        ];
        let page = merge_mailbox_pages(device, user, 10, 3, "a");
        assert_eq!(ids(&page), vec!["m1"]);
        assert_eq!(page.resume_cursor().user, StreamPosition(300, 0));
        assert_eq!(page.resume_cursor().device, StreamPosition(150, 0));
        assert!(page.has_more);
    }

    /// A full device read ends at 200; the user-only entry at 300 waits. The user cursor
    /// names its own last consumed row, 150, not the device's 200 or unissued user's 300.
    #[test]
    fn a_full_device_read_bounds_what_the_user_read_claims() {
        let device = vec![
            ("100-0".to_string(), Some(env_for("m1", "a"))),
            ("200-0".to_string(), Some(env_for("m2", "a"))),
        ];
        let user = vec![
            ("150-0".to_string(), Some(env_for("to-b", "b"))),
            ("300-0".to_string(), Some(env("user-only"))),
        ];
        let page = merge_mailbox_pages(device, user, 10, 2, "a");
        assert_eq!(ids(&page), vec!["m1", "m2"]);
        assert_eq!(page.resume_cursor().user, StreamPosition(150, 0));
        assert_eq!(page.resume_cursor().device, StreamPosition(200, 0));
        assert!(page.has_more);
    }

    /// Reads short of their limit are the whole of both streams: nothing waits, and the page
    /// is the end. Mutation: count a source full at `len > limit` — the first test above
    /// delivers m2.
    #[test]
    fn reads_short_of_the_limit_deliver_everything_and_end() {
        let user = vec![("300-0".to_string(), Some(env_for("to-b", "b")))];
        let device = vec![
            ("150-0".to_string(), Some(env_for("m1", "a"))),
            ("400-0".to_string(), Some(env_for("m2", "a"))),
        ];
        let page = merge_mailbox_pages(device, user, 10, 3, "a");
        assert_eq!(ids(&page), vec!["m1", "m2"]);
        assert!(!page.has_more);
        assert_eq!(page.resume_cursor().device, StreamPosition(400, 0));
        assert_eq!(page.resume_cursor().user, StreamPosition(300, 0));
    }

    /// CPU-only benchmark of the production merge, with cloning outside the timed region.
    /// Run with --release --ignored --nocapture; latency is reported, never asserted.
    #[test]
    #[ignore = "manual merge CPU benchmark"]
    fn mailbox_merge_cpu_benchmark() {
        let device: Vec<_> = (0..50)
            .map(|i| {
                let mut e = env(&format!("message-{i}"));
                e.encrypted_payload = vec![255; 1024];
                (format!("{}-0", 1000 + 2 * i), Some(e))
            })
            .collect();
        let user: Vec<_> = (0..50)
            .map(|i| {
                let mut e = if i < 40 {
                    device[i].1.as_ref().unwrap().clone()
                } else if i < 45 {
                    env_for(&format!("sibling-{i}"), "other")
                } else {
                    env(&format!("user-only-{i}"))
                };
                e.encrypted_payload = vec![255; 1024];
                (format!("{}-0", 1001 + 2 * i), Some(e))
            })
            .collect();
        let mut elapsed = std::time::Duration::ZERO;
        for _ in 0..1000 {
            let (d, u) = (device.clone(), user.clone());
            let started = std::time::Instant::now();
            let page = std::hint::black_box(merge_mailbox_pages(d, u, 50, 100, "dev"));
            elapsed += started.elapsed();
            assert_eq!(page.entries.len(), 50);
            assert_eq!(page.user_only(), 2);
            assert_eq!(page.sibling_skipped, 5);
            assert!(page.has_more);
        }
        eprintln!(
            "mailbox merge: {:.2} us/page (1000 pages, 50+50 inputs, 1 KiB payload)",
            elapsed.as_secs_f64() * 1e6 / 1000.0
        );
    }

    /// A page that delivered nothing and examined nothing leaves the cursor where it was.
    #[test]
    fn an_empty_page_resumes_where_it_started() {
        for start in [MailboxCursor::default(), "500-0".parse().unwrap()] {
            let page = super::merge_mailbox_pages(vec![], vec![], 10, 100, "a", start).unwrap();
            assert_eq!(page.resume_cursor(), start);
        }
    }
}
