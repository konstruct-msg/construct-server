//! One place where every Redis connection in this server gets its timings.
//!
//! ## Why this exists
//!
//! Four production call sites built a `ConnectionManager` — `construct-redis`,
//! `construct-queue`, `key-service`, `signaling-service` — and not one of them passed a
//! config. They therefore ran on whatever `redis-rs` happens to default to, which is a
//! thing that can change in a patch release of a dependency.
//!
//! That mattered more than it looks, because on 2026-09-13 the sealed-sender door was
//! given a circuit breaker: on a Redis outage the per-IP window degrades to a per-instance
//! counter and the Privacy Pass check is skipped rather than failed. **The breaker trips on
//! errors**, and the worst way Redis fails is not refusal but slowness — a server that is
//! swapping, blocked on an AOF fsync, or behind a partition answers nothing and returns
//! nothing. Without a response timeout there is no error, so the breaker never opens and
//! every send hangs instead: worse than either failing open or failing closed.
//!
//! It works today. `redis-rs` 1.2.0 defaults to a 500 ms response timeout and a 1 s
//! connection timeout (`src/client.rs:180-182`), so a hang does surface as an error. The
//! point of this module is that it works *because we chose it*, not because a dependency
//! currently agrees with us.
//!
//! ## The values
//!
//! `RESPONSE_TIMEOUT` and `CONNECT_TIMEOUT` are pinned at the values that were already in
//! effect, so adopting this module changes no behaviour — it only stops the behaviour from
//! being someone else's decision. Changing them is a separate, measured decision.
//!
//! `MAX_RECONNECT_DELAY` is the one addition. The library caps nothing by default
//! (`max_delay: None`), so the backoff is base 2 from 100 ms for 6 attempts — about 6.3 s
//! of sleeping on top of the connection timeouts, and unbounded growth the moment anyone
//! raises the retry count. A cap is what makes "how long can a reconnect hold a request"
//! a number rather than a product of two other knobs.

use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};

/// How long one command may take before it is an error.
///
/// Load-bearing for the sealed-door circuit breaker: this is the longest a hung Redis can
/// hold a send before the failure becomes visible as a failure.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// How long a single connection attempt may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Ceiling on the exponential reconnect backoff between attempts.
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// The connection settings every Redis client in this server uses.
pub fn connection_config() -> ConnectionManagerConfig {
    ConnectionManagerConfig::new()
        .set_response_timeout(Some(RESPONSE_TIMEOUT))
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_max_delay(MAX_RECONNECT_DELAY)
}

/// Connect to `url` with those settings.
///
/// Use this rather than `ConnectionManager::new` or `Client::get_connection_manager`:
/// both take the library's defaults, and a connection whose timeouts came from a
/// dependency's default is a connection nobody decided the timeouts for.
pub async fn connect(url: &str) -> redis::RedisResult<ConnectionManager> {
    let client = redis::Client::open(url)?;
    manager_for(client).await
}

/// Same, for callers that need to keep the `Client` (PubSub, which `ConnectionManager`
/// does not support).
pub async fn manager_for(client: redis::Client) -> redis::RedisResult<ConnectionManager> {
    ConnectionManager::new_with_config(client, connection_config()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The response timeout is the sealed door's circuit breaker made possible: without a
    /// finite one, a hung Redis produces no error, the breaker never opens, and sends hang
    /// rather than degrade. `Some(_)` is the whole claim — the exact number is a judgement,
    /// its existence is not.
    #[test]
    fn a_command_can_always_time_out() {
        let config = connection_config();
        assert_eq!(
            config.response_timeout(),
            Some(RESPONSE_TIMEOUT),
            "a connection with no response timeout cannot fail, only hang"
        );
    }

    /// Pinned at what was already in effect, so adopting this changed nothing. If these
    /// ever need to move, this test is the place that says the move was deliberate.
    #[test]
    fn the_pinned_values_match_what_was_previously_inherited() {
        assert_eq!(RESPONSE_TIMEOUT, Duration::from_millis(500));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(1));
    }

    /// Long enough that an ordinary command under load is not cut off, short enough that a
    /// hang is visible inside one send rather than a few.
    #[test]
    fn the_timeouts_are_within_a_sane_band() {
        assert!(RESPONSE_TIMEOUT >= Duration::from_millis(100));
        assert!(RESPONSE_TIMEOUT <= Duration::from_secs(2));
        assert!(CONNECT_TIMEOUT >= RESPONSE_TIMEOUT);
        assert!(MAX_RECONNECT_DELAY <= Duration::from_secs(5));
    }
}
