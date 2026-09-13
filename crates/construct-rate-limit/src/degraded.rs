// ============================================================================
// Degraded rate limiting — surviving a Redis outage without taking messaging down
// ============================================================================
//
// Rate limits live in Redis, and Redis is one container. Failing closed on a Redis
// error therefore made a single Redis hiccup a total messaging outage: every send
// from every device refused with retry_after=30, clients retrying into a wall.
//
// This module is the alternative. Two pieces:
//
//   1. A circuit breaker, so a Redis outage is detected once instead of re-discovered
//      (and re-timed-out) on every single send.
//   2. A bounded in-process counter used only while the breaker is open, so there is
//      still a ceiling on abuse during the outage — just an approximate, per-instance
//      one instead of an exact, shared one.
//
// Recovery is automatic: after a cooldown the breaker half-opens, one request probes
// Redis, and success closes it. No redeploy, no operator action.
//
// ── What is deliberately given up ───────────────────────────────────────────────
//
// With N messaging-service instances, the degraded ceiling is N × limit, because each
// process counts only what it saw. That is accepted: the point of degraded mode is a
// blast-radius cap during an outage, not exact enforcement. The exact limit returns
// with Redis.
//
// This matches the policy already stated for auth anti-bruteforce in construct-metrics
// ("fail-open on Redis for these controls, alert on sustained rate") — which is the
// *more* security-sensitive control. Sentinel failing closed was the outlier.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};

/// Consecutive Redis failures before the breaker opens. Small, because the failure we
/// are guarding against is total: one bad response is noise, five in a row is an outage.
const TRIP_THRESHOLD: u32 = 5;
/// How long the breaker stays open before letting one request probe Redis again.
const COOLDOWN_MS: i64 = 5_000;
/// Shard count for the fallback table — lock granularity only, not a capacity knob.
const SHARDS: usize = 16;
/// Hard cap on tracked keys across all shards. Bounds memory during an outage; see
/// `charge` for what happens at the cap.
const MAX_TRACKED_KEYS: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Redis is answering; it is authoritative.
    Closed,
    /// Redis is presumed down; skip it entirely and use the local fallback.
    Open,
    /// Cooldown elapsed; the next caller probes Redis once.
    HalfOpen,
}

/// Outcome of charging an event to the local fallback counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegradedOutcome {
    pub allowed: bool,
    /// False when the fallback table was at capacity and this key could not be counted.
    /// The event is allowed through; the flag exists so it can be metered rather than
    /// silently disappearing.
    pub tracked: bool,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    window_start: i64,
    count: u32,
}

#[derive(Default)]
struct Shard {
    entries: HashMap<u64, Entry>,
}

pub struct DegradedLimiter {
    consecutive_failures: AtomicU32,
    /// Unix millis until which the breaker is open. 0 = closed.
    open_until_ms: AtomicI64,
    shards: Vec<Mutex<Shard>>,
    tracked: AtomicUsize,
}

impl Default for DegradedLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl DegradedLimiter {
    pub fn new() -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            open_until_ms: AtomicI64::new(0),
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
            tracked: AtomicUsize::new(0),
        }
    }

    // ── Breaker ─────────────────────────────────────────────────────────────────

    pub fn state(&self, now_ms: i64) -> BreakerState {
        let open_until = self.open_until_ms.load(Ordering::Relaxed);
        if open_until == 0 {
            BreakerState::Closed
        } else if now_ms < open_until {
            BreakerState::Open
        } else {
            BreakerState::HalfOpen
        }
    }

    /// True when Redis should not even be attempted — the cost of an outage is not one
    /// error, it is one *timeout* per send, which is what turns a Redis blip into a
    /// latency collapse.
    pub fn should_skip_redis(&self, now_ms: i64) -> bool {
        self.state(now_ms) == BreakerState::Open
    }

    /// Redis answered. Closes the breaker and forgets the failure streak.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.open_until_ms.store(0, Ordering::Relaxed);
    }

    /// Redis failed. Returns true if this failure is the one that opened the breaker,
    /// so the caller can log the transition once instead of per request.
    pub fn record_failure(&self, now_ms: i64) -> bool {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures < TRIP_THRESHOLD {
            return false;
        }
        // A half-open probe that fails re-arms the cooldown rather than flapping.
        let was_open = self
            .open_until_ms
            .swap(now_ms + COOLDOWN_MS, Ordering::Relaxed)
            != 0;
        !was_open
    }

    // ── Local fallback counter ──────────────────────────────────────────────────

    /// Count one event for `key` in a fixed window and say whether it may proceed.
    ///
    /// At capacity the event is **allowed and reported untracked** rather than denied.
    /// Denying here would recreate the very outage this module exists to prevent, and
    /// the cap is not a cheap thing for an attacker to reach: `device_id` comes from a
    /// verified caller, so filling the table means registering 50k devices past
    /// registration's own defences.
    pub fn charge(
        &self,
        key: &str,
        limit: i32,
        window_secs: i64,
        now_secs: i64,
    ) -> DegradedOutcome {
        if limit <= 0 {
            return DegradedOutcome {
                allowed: false,
                tracked: true,
            };
        }
        let window_start = now_secs - now_secs.rem_euclid(window_secs.max(1));
        let hash = fxhash(key);
        let shard_idx = (hash % SHARDS as u64) as usize;

        let mut shard = match self.shards[shard_idx].lock() {
            Ok(guard) => guard,
            // A panic while holding the lock must not take the send path with it.
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(entry) = shard.entries.get_mut(&hash) {
            if entry.window_start == window_start {
                entry.count = entry.count.saturating_add(1);
                return DegradedOutcome {
                    allowed: entry.count <= limit as u32,
                    tracked: true,
                };
            }
            // Stale window — reuse the slot, no capacity change.
            *entry = Entry {
                window_start,
                count: 1,
            };
            return DegradedOutcome {
                allowed: true,
                tracked: true,
            };
        }

        if self.tracked.load(Ordering::Relaxed) >= MAX_TRACKED_KEYS {
            let dropped = purge_stale(&mut shard, window_start);
            if dropped > 0 {
                self.tracked.fetch_sub(dropped, Ordering::Relaxed);
            }
            if self.tracked.load(Ordering::Relaxed) >= MAX_TRACKED_KEYS {
                return DegradedOutcome {
                    allowed: true,
                    tracked: false,
                };
            }
        }

        shard.entries.insert(
            hash,
            Entry {
                window_start,
                count: 1,
            },
        );
        self.tracked.fetch_add(1, Ordering::Relaxed);
        DegradedOutcome {
            allowed: true,
            tracked: true,
        }
    }

    /// Drop every window that is no longer current. Called when Redis comes back, so an
    /// outage does not leave its counters resident until they happen to be touched again.
    pub fn clear(&self) {
        for shard in &self.shards {
            let mut guard = match shard.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.entries.clear();
        }
        self.tracked.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.tracked.load(Ordering::Relaxed)
    }
}

fn purge_stale(shard: &mut Shard, window_start: i64) -> usize {
    let before = shard.entries.len();
    shard.entries.retain(|_, e| e.window_start == window_start);
    before - shard.entries.len()
}

/// Small, fast, non-cryptographic hash. Rate-limit keys are authenticated device/user
/// ids, not attacker-chosen strings, so collision resistance is not load-bearing —
/// collisions only make two peers share a degraded-mode budget for one window.
fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Breaker ─────────────────────────────────────────────────────────────

    #[test]
    fn breaker_starts_closed_and_tolerates_isolated_failures() {
        let l = DegradedLimiter::new();
        assert_eq!(l.state(0), BreakerState::Closed);
        for _ in 0..(TRIP_THRESHOLD - 1) {
            assert!(!l.record_failure(0));
        }
        assert_eq!(
            l.state(0),
            BreakerState::Closed,
            "a streak short of the threshold must not trip"
        );
    }

    #[test]
    fn breaker_opens_on_a_sustained_streak_and_reports_the_transition_once() {
        let l = DegradedLimiter::new();
        let mut transitions = 0;
        for _ in 0..(TRIP_THRESHOLD + 4) {
            if l.record_failure(1_000) {
                transitions += 1;
            }
        }
        assert_eq!(
            transitions, 1,
            "the open transition must be logged once, not per request"
        );
        assert_eq!(l.state(1_000), BreakerState::Open);
        assert!(l.should_skip_redis(1_000));
    }

    #[test]
    fn a_success_resets_the_streak() {
        let l = DegradedLimiter::new();
        for _ in 0..(TRIP_THRESHOLD - 1) {
            l.record_failure(0);
        }
        l.record_success();
        for _ in 0..(TRIP_THRESHOLD - 1) {
            assert!(
                !l.record_failure(0),
                "streak must restart from zero after a success"
            );
        }
    }

    #[test]
    fn breaker_half_opens_after_the_cooldown_and_probes_redis() {
        let l = DegradedLimiter::new();
        for _ in 0..TRIP_THRESHOLD {
            l.record_failure(1_000);
        }
        assert_eq!(l.state(1_000 + COOLDOWN_MS - 1), BreakerState::Open);
        assert_eq!(l.state(1_000 + COOLDOWN_MS), BreakerState::HalfOpen);
        assert!(
            !l.should_skip_redis(1_000 + COOLDOWN_MS),
            "half-open must let a request reach Redis, otherwise it never recovers"
        );
    }

    #[test]
    fn a_failed_probe_re_arms_the_cooldown_without_re_logging() {
        let l = DegradedLimiter::new();
        for _ in 0..TRIP_THRESHOLD {
            l.record_failure(1_000);
        }
        let probe_at = 1_000 + COOLDOWN_MS;
        assert!(
            !l.record_failure(probe_at),
            "already-open breaker must not re-announce"
        );
        assert_eq!(
            l.state(probe_at),
            BreakerState::Open,
            "cooldown restarts from the probe"
        );
    }

    #[test]
    fn recovery_closes_the_breaker() {
        let l = DegradedLimiter::new();
        for _ in 0..TRIP_THRESHOLD {
            l.record_failure(1_000);
        }
        l.record_success();
        assert_eq!(l.state(1_000), BreakerState::Closed);
        assert!(!l.should_skip_redis(1_000));
    }

    // ── Fallback counter ────────────────────────────────────────────────────

    #[test]
    fn fallback_allows_exactly_the_limit_then_denies() {
        let l = DegradedLimiter::new();
        for i in 1..=10 {
            let out = l.charge("dev", 10, 3600, 0);
            assert!(out.allowed, "send {i} of 10 must pass");
            assert!(out.tracked);
        }
        assert!(
            !l.charge("dev", 10, 3600, 0).allowed,
            "the 11th is over the ceiling"
        );
    }

    #[test]
    fn fallback_windows_reset() {
        let l = DegradedLimiter::new();
        for _ in 0..11 {
            l.charge("dev", 10, 3600, 0);
        }
        assert!(!l.charge("dev", 10, 3600, 0).allowed);
        assert!(
            l.charge("dev", 10, 3600, 3600).allowed,
            "next window starts clean"
        );
    }

    #[test]
    fn fallback_keeps_devices_independent() {
        let l = DegradedLimiter::new();
        for _ in 0..11 {
            l.charge("noisy", 10, 3600, 0);
        }
        assert!(!l.charge("noisy", 10, 3600, 0).allowed);
        assert!(
            l.charge("quiet", 10, 3600, 0).allowed,
            "one device must not spend another's budget"
        );
    }

    #[test]
    fn a_zero_limit_is_refused_without_allocating() {
        let l = DegradedLimiter::new();
        assert!(!l.charge("banned", 0, 3600, 0).allowed);
        assert_eq!(l.tracked_keys(), 0);
    }

    /// The cap is the memory bound. Reaching it must allow-and-report, never deny —
    /// denying at capacity would reproduce the outage this module exists to prevent.
    #[test]
    fn at_capacity_events_are_allowed_but_reported_untracked() {
        let l = DegradedLimiter::new();
        for i in 0..MAX_TRACKED_KEYS {
            l.charge(&format!("dev-{i}"), 10, 3600, 0);
        }
        assert_eq!(l.tracked_keys(), MAX_TRACKED_KEYS);

        let out = l.charge("one-too-many", 10, 3600, 0);
        assert!(out.allowed, "must not deny at capacity");
        assert!(!out.tracked, "but must say it could not be counted");
    }

    /// Capacity pressure from a *previous* window must not permanently wedge the table.
    #[test]
    fn stale_windows_are_purged_to_make_room() {
        let l = DegradedLimiter::new();
        for i in 0..MAX_TRACKED_KEYS {
            l.charge(&format!("dev-{i}"), 10, 3600, 0);
        }
        let out = l.charge("fresh", 10, 3600, 3600);
        assert!(out.allowed);
        assert!(
            out.tracked,
            "the previous window's keys must be reclaimable"
        );
    }

    #[test]
    fn clear_releases_everything() {
        let l = DegradedLimiter::new();
        for i in 0..100 {
            l.charge(&format!("dev-{i}"), 10, 3600, 0);
        }
        assert_eq!(l.tracked_keys(), 100);
        l.clear();
        assert_eq!(l.tracked_keys(), 0);
    }

    #[test]
    fn windows_are_aligned_not_relative_to_first_use() {
        let l = DegradedLimiter::new();
        // Two charges either side of an hour boundary belong to different windows even
        // though they are only two seconds apart.
        assert!(l.charge("dev", 1, 3600, 3599).allowed);
        assert!(l.charge("dev", 1, 3600, 3601).allowed);
    }
}
