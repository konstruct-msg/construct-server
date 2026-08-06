// ============================================================================
// In-process sliding-window rate limiter (single media instance)
// ============================================================================
//
// media-service is deployed as one instance (see main SCALING NOTE). This avoids
// a Redis dependency for mint throttling. If we multi-instance later, swap for
// construct-rate-limit + Redis.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Sliding window counter keyed by user id.
pub struct SlidingWindowLimiter {
    inner: Mutex<HashMap<Uuid, Vec<Instant>>>,
    max: u32,
    window: Duration,
}

impl SlidingWindowLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max: max_per_window.max(1),
            window,
        }
    }

    /// Record one event. Returns `false` if the caller is over the limit
    /// (event is NOT recorded when over limit).
    pub fn check_and_record(&self, user_id: Uuid) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entries = map.entry(user_id).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() as u32 >= self.max {
            return false;
        }
        entries.push(now);
        // Opportunistic prune of empty-ish map growth for many unique users
        if map.len() > 10_000 {
            map.retain(|_, v| !v.is_empty());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_window_limit() {
        let lim = SlidingWindowLimiter::new(2, Duration::from_secs(3600));
        let u = Uuid::new_v4();
        assert!(lim.check_and_record(u));
        assert!(lim.check_and_record(u));
        assert!(!lim.check_and_record(u));
    }
}
