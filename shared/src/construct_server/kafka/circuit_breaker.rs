// ============================================================================
// Circuit Breaker for Kafka Producer
// ============================================================================
//
// Prevents cascading failures when Kafka is slow or unavailable.
//
// Problem:
// - If Kafka is slow (e.g., 10s latency), all send_message() calls block
// - HTTP threads get exhausted → entire API becomes unresponsive
// - All endpoints fail, even those not using Kafka
//
// Solution:
// - Circuit Breaker tracks failures and latency
// - After threshold failures, "opens" circuit (fail fast)
// - Periodically tries to recover ("half-open" state)
// - Prevents thread pool exhaustion
//
// States:
// - CLOSED: Normal operation, requests go through
// - OPEN: Too many failures, reject immediately with error
// - HALF_OPEN: Testing if service recovered, allow limited requests
//
// Configuration:
// - failure_threshold: Open circuit after N consecutive failures (default: 5)
// - timeout: Per-request timeout (default: 3s)
// - reset_timeout: How long to wait before trying half-open (default: 30s)
//
// ============================================================================

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit Breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening circuit
    pub failure_threshold: u32,
    /// Timeout for each operation
    pub timeout: Duration,
    /// Time to wait before attempting recovery (half-open)
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout: Duration::from_secs(3),
            reset_timeout: Duration::from_secs(30),
        }
    }
}

/// Circuit Breaker error types
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open (too many failures), request rejected immediately
    #[error("Circuit breaker is OPEN - service unavailable (last failure: {0:?} ago)")]
    Open(Duration),

    /// Operation timed out
    #[error("Circuit breaker timeout ({timeout:?}) exceeded")]
    Timeout { timeout: Duration },

    /// Underlying operation failed
    #[error("Operation failed: {0}")]
    Inner(#[source] E),
}

/// Circuit Breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Normal operation
    Closed,
    /// Too many failures, rejecting requests
    Open,
    /// Testing if service recovered
    HalfOpen,
}

/// Circuit Breaker implementation
///
/// Thread-safe circuit breaker that protects against cascading failures.
pub struct CircuitBreaker {
    /// Consecutive failure count
    failures: AtomicU32,
    /// Is circuit open?
    is_open: AtomicBool,
    /// Timestamp of last failure (for reset_timeout)
    last_failure: RwLock<Option<Instant>>,
    /// Configuration
    config: CircuitBreakerConfig,
    /// Success count (for half-open state)
    half_open_successes: AtomicU32,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default configuration
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom configuration
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            failures: AtomicU32::new(0),
            is_open: AtomicBool::new(false),
            last_failure: RwLock::new(None),
            config,
            half_open_successes: AtomicU32::new(0),
        }
    }

    /// Execute an operation with circuit breaker protection
    ///
    /// # Type Parameters
    /// * `F` - Future that performs the operation
    /// * `T` - Success type
    /// * `E` - Error type
    ///
    /// # Returns
    /// * `Ok(T)` - Operation succeeded
    /// * `Err(CircuitBreakerError::Open)` - Circuit is open, request rejected
    /// * `Err(CircuitBreakerError::Timeout)` - Operation timed out
    /// * `Err(CircuitBreakerError::Inner(E))` - Operation failed
    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        // Check if circuit is open
        if self.is_open.load(Ordering::Relaxed) {
            let last_failure_time = {
                let last = self.last_failure.read().await;
                *last
            };

            if let Some(last_failure) = last_failure_time {
                let elapsed = last_failure.elapsed();

                // Check if we should try half-open
                if elapsed >= self.config.reset_timeout {
                    tracing::info!(
                        elapsed_seconds = elapsed.as_secs(),
                        "Circuit breaker attempting recovery (half-open state)"
                    );
                    // Fall through to execute request (half-open)
                } else {
                    // Still open, reject immediately
                    tracing::warn!(
                        elapsed_seconds = elapsed.as_secs(),
                        reset_timeout_seconds = self.config.reset_timeout.as_secs(),
                        "Circuit breaker OPEN - rejecting request"
                    );
                    return Err(CircuitBreakerError::Open(elapsed));
                }
            }
        }

        // Execute operation with timeout
        let result = tokio::time::timeout(self.config.timeout, f).await;

        match result {
            // Timeout
            Err(_timeout_elapsed) => {
                self.record_failure().await;
                tracing::warn!(
                    timeout_ms = self.config.timeout.as_millis(),
                    "Circuit breaker timeout"
                );
                Err(CircuitBreakerError::Timeout {
                    timeout: self.config.timeout,
                })
            }
            // Success
            Ok(Ok(value)) => {
                self.record_success().await;
                Ok(value)
            }
            // Operation failed
            Ok(Err(error)) => {
                self.record_failure().await;
                Err(CircuitBreakerError::Inner(error))
            }
        }
    }

    /// Record a successful operation
    async fn record_success(&self) {
        let was_open = self.is_open.load(Ordering::Relaxed);

        if was_open {
            // In half-open state, need multiple successes to close
            let successes = self.half_open_successes.fetch_add(1, Ordering::Relaxed) + 1;

            if successes >= 2 {
                // Recovered! Close circuit
                self.is_open.store(false, Ordering::Relaxed);
                self.failures.store(0, Ordering::Relaxed);
                self.half_open_successes.store(0, Ordering::Relaxed);

                tracing::info!("Circuit breaker CLOSED - service recovered");
            } else {
                tracing::info!(
                    successes = successes,
                    "Circuit breaker half-open - success recorded"
                );
            }
        } else {
            // Normal operation, reset failure count
            self.failures.store(0, Ordering::Relaxed);
            self.half_open_successes.store(0, Ordering::Relaxed);
        }
    }

    /// Record a failed operation
    async fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;

        // Update last failure timestamp
        {
            let mut last = self.last_failure.write().await;
            *last = Some(Instant::now());
        }

        // Check if we should open circuit
        if failures >= self.config.failure_threshold {
            let was_open = self.is_open.swap(true, Ordering::Relaxed);

            if !was_open {
                tracing::error!(
                    failures = failures,
                    threshold = self.config.failure_threshold,
                    reset_timeout_seconds = self.config.reset_timeout.as_secs(),
                    "Circuit breaker OPENED - too many failures"
                );
            }

            // Reset half-open success counter
            self.half_open_successes.store(0, Ordering::Relaxed);
        } else {
            tracing::warn!(
                failures = failures,
                threshold = self.config.failure_threshold,
                "Circuit breaker failure recorded"
            );
        }
    }

    /// Get current state (for monitoring/debugging)
    pub async fn get_state(&self) -> (State, u32, Option<Instant>) {
        let is_open = self.is_open.load(Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        let last_failure = {
            let last = self.last_failure.read().await;
            *last
        };

        let state = if is_open {
            if let Some(last) = last_failure {
                if last.elapsed() >= self.config.reset_timeout {
                    State::HalfOpen
                } else {
                    State::Open
                }
            } else {
                State::Open
            }
        } else {
            State::Closed
        };

        (state, failures, last_failure)
    }

    /// Force circuit to close (for testing or manual recovery)
    pub async fn force_close(&self) {
        self.is_open.store(false, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.half_open_successes.store(0, Ordering::Relaxed);

        let mut last = self.last_failure.write().await;
        *last = None;

        tracing::info!("Circuit breaker manually CLOSED");
    }

    /// Force circuit to open (for testing or manual intervention)
    #[allow(dead_code)]
    pub async fn force_open(&self) {
        self.is_open.store(true, Ordering::Relaxed);
        self.failures
            .store(self.config.failure_threshold, Ordering::Relaxed);

        let mut last = self.last_failure.write().await;
        *last = Some(Instant::now());

        tracing::warn!("Circuit breaker manually OPENED");
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;

    #[tokio::test]
    async fn test_circuit_breaker_closed_on_success() {
        let cb = CircuitBreaker::new();
        let counter = Arc::new(AtomicU32::new(0));

        // Successful operation
        let result = cb
            .call(async {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok::<_, anyhow::Error>(42)
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        let (state, failures, _) = cb.get_state().await;
        assert_eq!(state, State::Closed);
        assert_eq!(failures, 0);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            timeout: Duration::from_secs(1),
            reset_timeout: Duration::from_secs(30),
        };
        let cb = CircuitBreaker::with_config(config);
        let counter = Arc::new(AtomicU32::new(0));

        // Fail 3 times
        for _ in 0..3 {
            let counter = counter.clone();
            let result = cb
                .call(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    Err::<i32, _>(anyhow::anyhow!("simulated failure"))
                })
                .await;

            assert!(result.is_err());
        }

        assert_eq!(counter.load(Ordering::Relaxed), 3);

        let (state, failures, _) = cb.get_state().await;
        assert_eq!(state, State::Open);
        assert_eq!(failures, 3);

        // Next request should be rejected without executing
        let counter_before = counter.load(Ordering::Relaxed);
        let result = cb
            .call(async {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok::<_, anyhow::Error>(42)
            })
            .await;

        assert!(matches!(result, Err(CircuitBreakerError::Open(_))));
        // Counter should NOT have incremented (operation not executed)
        assert_eq!(counter.load(Ordering::Relaxed), counter_before);
    }

    #[tokio::test]
    async fn test_circuit_breaker_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            timeout: Duration::from_millis(100),
            reset_timeout: Duration::from_secs(30),
        };
        let cb = CircuitBreaker::with_config(config);

        // Operation that takes too long
        let result = cb
            .call(async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok::<_, anyhow::Error>(42)
            })
            .await;

        assert!(matches!(result, Err(CircuitBreakerError::Timeout { .. })));

        let (state, failures, _) = cb.get_state().await;
        assert_eq!(failures, 1);
        assert_eq!(state, State::Closed); // Not enough failures to open yet
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_secs(1),
            reset_timeout: Duration::from_millis(100), // Short for testing
        };
        let cb = CircuitBreaker::with_config(config);

        // Fail twice to open circuit
        for _ in 0..2 {
            let _ = cb
                .call(async { Err::<i32, _>(anyhow::anyhow!("fail")) })
                .await;
        }

        let (state, _, _) = cb.get_state().await;
        assert_eq!(state, State::Open);

        // Wait for reset_timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        let (state, _, _) = cb.get_state().await;
        assert_eq!(state, State::HalfOpen);

        // Succeed twice to close circuit
        for _ in 0..2 {
            let result = cb.call(async { Ok::<_, anyhow::Error>(42) }).await;
            assert!(result.is_ok());
        }

        let (state, failures, _) = cb.get_state().await;
        assert_eq!(state, State::Closed);
        assert_eq!(failures, 0);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_fails_again() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_secs(1),
            reset_timeout: Duration::from_millis(100),
        };
        let cb = CircuitBreaker::with_config(config);

        // Open circuit
        for _ in 0..2 {
            let _ = cb
                .call(async { Err::<i32, _>(anyhow::anyhow!("fail")) })
                .await;
        }

        // Wait for half-open
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Fail in half-open state
        let result = cb
            .call(async { Err::<i32, _>(anyhow::anyhow!("fail again")) })
            .await;
        assert!(result.is_err());

        // Should go back to open
        let (state, _, _) = cb.get_state().await;
        assert_eq!(state, State::Open);
    }

    #[tokio::test]
    async fn test_force_close() {
        let cb = CircuitBreaker::new();

        // Open circuit
        for _ in 0..5 {
            let _ = cb
                .call(async { Err::<i32, _>(anyhow::anyhow!("fail")) })
                .await;
        }

        let (state, _, _) = cb.get_state().await;
        assert_eq!(state, State::Open);

        // Force close
        cb.force_close().await;

        let (state, failures, last_failure) = cb.get_state().await;
        assert_eq!(state, State::Closed);
        assert_eq!(failures, 0);
        assert!(last_failure.is_none());

        // Should accept requests now
        let result = cb.call(async { Ok::<_, anyhow::Error>(42) }).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let cb = Arc::new(CircuitBreaker::new());
        let mut handles = vec![];

        // Execute 100 concurrent requests
        for i in 0..100 {
            let cb = cb.clone();
            let handle = tokio::spawn(async move {
                cb.call(async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok::<_, anyhow::Error>(i)
                })
                .await
            });
            handles.push(handle);
        }

        // Wait for all
        let mut successes = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                successes += 1;
            }
        }

        assert_eq!(successes, 100);

        let (state, failures, _) = cb.get_state().await;
        assert_eq!(state, State::Closed);
        assert_eq!(failures, 0);
    }
}
