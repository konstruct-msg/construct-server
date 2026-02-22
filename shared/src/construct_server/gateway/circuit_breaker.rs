// ============================================================================
// Circuit Breaker - Phase 2.6.6
// ============================================================================
//
// Circuit breaker pattern for service resilience.
// Prevents cascading failures by stopping requests to failing services.
//
// States:
// - Closed: Normal operation, requests pass through
// - Open: Service is failing, requests are rejected immediately
// - Half-Open: Testing if service recovered, allowing limited requests
//
// ============================================================================

use construct_config::CircuitBreakerConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Closed: Normal operation
    Closed,
    /// Open: Service is failing, reject requests
    Open,
    /// Half-Open: Testing recovery
    HalfOpen,
}

/// Circuit breaker for a service
#[derive(Clone)]
pub struct CircuitBreaker {
    config: Arc<CircuitBreakerConfig>,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<RwLock<u32>>,
    success_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    opened_at: Arc<RwLock<Option<Instant>>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(config: Arc<CircuitBreakerConfig>) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
            success_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            opened_at: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if request should be allowed
    /// Returns Ok(()) if request should proceed, Err if circuit is open
    pub async fn allow_request(&self) -> Result<(), CircuitBreakerError> {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => {
                // Normal operation
                Ok(())
            }
            CircuitState::Open => {
                // Check if timeout has passed, transition to half-open
                let opened_at = *self.opened_at.read().await;
                if let Some(opened) = opened_at {
                    let elapsed = opened.elapsed();
                    if elapsed >= Duration::from_secs(self.config.timeout_secs) {
                        // Timeout passed, try half-open
                        let mut state_guard = self.state.write().await;
                        *state_guard = CircuitState::HalfOpen;
                        // Reset success count for half-open testing
                        *self.success_count.write().await = 0;
                        drop(state_guard);
                        tracing::info!("Circuit breaker transitioning to half-open");
                        Ok(())
                    } else {
                        // Still in timeout period
                        Err(CircuitBreakerError::CircuitOpen)
                    }
                } else {
                    // Should not happen, but handle gracefully
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests to test recovery
                Ok(())
            }
        }
    }

    /// Record a successful request
    pub async fn record_success(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                *self.failure_count.write().await = 0;
            }
            CircuitState::HalfOpen => {
                // Increment success count
                let mut success_guard = self.success_count.write().await;
                *success_guard += 1;

                // If we have enough successes, close the circuit
                if *success_guard >= self.config.success_threshold {
                    let mut state_guard = self.state.write().await;
                    *state_guard = CircuitState::Closed;
                    *self.failure_count.write().await = 0;
                    *self.success_count.write().await = 0;
                    *self.opened_at.write().await = None;
                    drop(state_guard);
                    tracing::info!("Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Open => {
                // Should not happen, but ignore
            }
        }
    }

    /// Record a failed request
    pub async fn record_failure(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => {
                // Increment failure count
                let mut failure_guard = self.failure_count.write().await;
                *failure_guard += 1;
                *self.last_failure_time.write().await = Some(Instant::now());

                // If threshold reached, open the circuit
                if *failure_guard >= self.config.failure_threshold {
                    let mut state_guard = self.state.write().await;
                    *state_guard = CircuitState::Open;
                    *self.opened_at.write().await = Some(Instant::now());
                    drop(state_guard);
                    tracing::warn!(
                        failure_count = *failure_guard,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker opened due to failures"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open immediately opens the circuit
                let mut state_guard = self.state.write().await;
                *state_guard = CircuitState::Open;
                *self.opened_at.write().await = Some(Instant::now());
                *self.success_count.write().await = 0;
                drop(state_guard);
                tracing::warn!("Circuit breaker reopened after failure in half-open state");
            }
            CircuitState::Open => {
                // Already open, just update failure time
                *self.last_failure_time.write().await = Some(Instant::now());
            }
        }
    }

    /// Get current state (for metrics)
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    /// Get failure count (for metrics)
    pub async fn failure_count(&self) -> u32 {
        *self.failure_count.read().await
    }
}

/// Circuit breaker error
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is open - service is unavailable")]
    CircuitOpen,
}
