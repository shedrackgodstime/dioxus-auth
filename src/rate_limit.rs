//! Authentication rate limiting.

use std::collections::BTreeMap;
use std::sync::Arc;
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
    #[must_use = "the rate-limit check must be used"]
    fn check(&self, identifier: &str) -> Result<(), AuthError>;

    /// Records a failed authentication attempt for the identifier.
    fn record_attempt(&self, identifier: &str);

    /// Records a successful authentication, resetting the identifier's counters.
    fn record_success(&self, identifier: &str);
}

/// Default rate-limit window: 15 minutes, in seconds.
const DEFAULT_WINDOW_SECS: u64 = 15 * 60;

/// Wall-clock source producing the current instant.
pub type RateLimiterClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// In-memory sliding-window rate limiter.
///
/// Tracks failed login attempts per identifier within a rolling time window.
/// After `max_attempts` failures within `window`, further attempts are rejected.
/// A successful login resets the counter for that identifier.
///
/// Process-local and best-effort. For distributed deployments, implement
/// `RateLimiter` with Redis, Memcached, or similar.
pub struct InMemoryRateLimiter {
    max_attempts: usize,
    window: Duration,
    attempts: RwLock<BTreeMap<String, Vec<SystemTime>>>,
    now: RateLimiterClock,
}

impl std::fmt::Debug for InMemoryRateLimiter {
    // reason: the clock is a closure and carries nothing debuggable; elide it
    // rather than derive a Debug that cannot hold the field.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return f
            .debug_struct("InMemoryRateLimiter")
            .field("max_attempts", &self.max_attempts)
            .field("window", &self.window)
            .finish_non_exhaustive();
    }
}

impl Default for InMemoryRateLimiter {
    /// 10 failed attempts per 15-minute window.
    fn default() -> Self {
        return Self::new(10, Duration::from_secs(DEFAULT_WINDOW_SECS));
    }
}

impl InMemoryRateLimiter {
    /// Creates a new in-memory rate limiter on the system clock.
    ///
    /// * `max_attempts` — maximum failed attempts allowed within `window`
    /// * `window` — rolling time window for counting attempts
    #[must_use]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        return Self::with_clock(max_attempts, window, Arc::new(SystemTime::now));
    }

    /// Creates a new in-memory rate limiter on a custom clock.
    ///
    /// Tests inject a deterministic clock to exercise window expiry without
    /// sleeping.
    ///
    /// * `max_attempts` — maximum failed attempts allowed within `window`
    /// * `window` — rolling time window for counting attempts
    /// * `now` — clock producing the current instant
    #[must_use]
    pub fn with_clock(max_attempts: usize, window: Duration, now: RateLimiterClock) -> Self {
        return Self {
            max_attempts,
            window,
            attempts: RwLock::new(BTreeMap::new()),
            now,
        };
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn check(&self, identifier: &str) -> Result<(), AuthError> {
        let now = (self.now)();
        let limited = {
            let mut attempts = self.attempts.write();
            attempts.get_mut(identifier).is_some_and(|timestamps| {
                timestamps.retain(|t| {
                    return now.duration_since(*t).is_ok_and(|d| return d < self.window);
                });
                return timestamps.len() >= self.max_attempts;
            })
        };
        if limited {
            return Err(AuthError::RateLimited);
        }
        return Ok(());
    }

    fn record_attempt(&self, identifier: &str) {
        let now = (self.now)();
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
