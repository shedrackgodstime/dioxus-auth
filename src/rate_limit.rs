//! Authentication rate limiting.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;

use crate::error::AuthError;

/// Capability for rate limiting authentication attempts.
pub trait RateLimiter: std::fmt::Debug + Send + Sync {
    /// Checks whether the identifier is currently rate-limited.
    ///
    /// Returns `Ok(())` if the attempt is allowed, or `Err(AuthError::RateLimited)`
    /// if the identifier has exceeded the allowed attempt count within the window.
    ///
    /// # Errors
    /// Returns [`AuthError::RateLimited`] when the identifier has exceeded the
    /// allowed attempt count within the window.
    fn check(&self, identifier: &str) -> Result<(), AuthError>;

    /// Records a failed authentication attempt for the identifier.
    fn record_attempt(&self, identifier: &str);

    /// Records a successful authentication, resetting the identifier's counters.
    fn record_success(&self, identifier: &str);
}

/// In-memory sliding-window rate limiter.
///
/// Tracks failed login attempts per identifier within a rolling time window.
/// After `max_attempts` failures within `window`, further attempts are rejected.
/// A successful login resets the counter for that identifier.
///
/// Process-local and best-effort. For distributed deployments, implement
/// `RateLimiter` with Redis, Memcached, or similar.
#[derive(Debug, Default)]
pub struct InMemoryRateLimiter {
    max_attempts: usize,
    window: Duration,
    attempts: RwLock<BTreeMap<String, Vec<SystemTime>>>,
}

impl InMemoryRateLimiter {
    /// Creates a new in-memory rate limiter.
    ///
    /// * `max_attempts` — maximum failed attempts allowed within `window`
    /// * `window` — rolling time window for counting attempts
    #[must_use]
    pub const fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            attempts: RwLock::new(BTreeMap::new()),
        }
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn check(&self, identifier: &str) -> Result<(), AuthError> {
        let now = SystemTime::now();
        let limited = {
            let mut attempts = self.attempts.write();
            attempts
                .get_mut(identifier)
                .is_some_and(|timestamps| {
                    timestamps.retain(|t| now.duration_since(*t).is_ok_and(|d| d < self.window));
                    timestamps.len() >= self.max_attempts
                })
        };
        if limited {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    fn record_attempt(&self, identifier: &str) {
        let now = SystemTime::now();
        let mut attempts = self.attempts.write();
        attempts
            .entry(identifier.to_string())
            .or_default()
            .push(now);
    }

    fn record_success(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        attempts.remove(identifier);
    }
}