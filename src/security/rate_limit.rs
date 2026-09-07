use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::error::{AuthError, AuthResult};

/// Trait for rate limiting authentication attempts.
///
/// Implementations decide how to track attempts per identifier and whether to
/// allow or reject a new attempt.
pub trait RateLimiter: Send + Sync + 'static {
    /// Check whether the identifier is currently rate-limited.
    ///
    /// Returns `Ok(())` if the attempt is allowed, or `Err(AuthError::RateLimited)`
    /// if the identifier has exceeded the allowed attempt count within the window.
    fn check(&self, identifier: &str) -> AuthResult<()>;

    /// Record a failed authentication attempt for the identifier.
    fn record_attempt(&self, identifier: &str);

    /// Record a successful authentication attempt, resetting the identifier's counters.
    fn record_success(&self, identifier: &str);
}

/// In-memory sliding-window rate limiter.
///
/// Tracks failed login attempts per identifier within a rolling time window.
/// After `max_attempts` failures within `window`, further attempts are rejected.
/// A successful login resets the counter for that identifier.
///
/// This implementation is best-effort and process-local. For distributed
/// deployments, implement `RateLimiter` with Redis, Memcached, or similar.
pub struct InMemoryRateLimiter {
    max_attempts: usize,
    window: Duration,
    attempts: Mutex<HashMap<String, Vec<SystemTime>>>,
}

impl InMemoryRateLimiter {
    /// Create a new in-memory rate limiter.
    ///
    /// * `max_attempts` - maximum failed attempts allowed within `window`
    /// * `window` - rolling time window for counting attempts
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            attempts: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn check(&self, identifier: &str) -> AuthResult<()> {
        let now = SystemTime::now();
        let mut attempts = self.attempts.lock().unwrap();

        if let Some(timestamps) = attempts.get_mut(identifier) {
            timestamps.retain(|&t| now.duration_since(t).unwrap_or_default() < self.window);

            if timestamps.len() >= self.max_attempts {
                return Err(AuthError::RateLimited);
            }
        }

        Ok(())
    }

    fn record_attempt(&self, identifier: &str) {
        let now = SystemTime::now();
        let mut attempts = self.attempts.lock().unwrap();
        attempts
            .entry(identifier.to_string())
            .or_default()
            .push(now);
    }

    fn record_success(&self, identifier: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(identifier);
    }
}
