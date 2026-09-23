//! Authentication rate limiting.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;

use crate::error::AuthError;

/// Capability for rate limiting authentication attempts.
///
/// Keys are pre-normalized by the engine: every credential path funnels through
/// the gate helpers, which trim and lowercase the identifier once, so an
/// implementation receives one canonical key per identifier and must not
/// normalize again.
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

/// Default ceiling on simultaneously tracked identifiers.
const DEFAULT_MAX_TRACKED_IDENTIFIERS: usize = 10_000;

/// Drops attempts that have lapsed out of the window.
fn prune_expired(timestamps: &mut Vec<SystemTime>, now: SystemTime, window: Duration) {
    timestamps.retain(|attempt| {
        return now
            .duration_since(*attempt)
            .is_ok_and(|elapsed| return elapsed < window);
    });
}

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
    max_tracked: usize,
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
            .field("max_tracked", &self.max_tracked)
            .finish_non_exhaustive();
    }
}

impl Default for InMemoryRateLimiter {
    /// 10 failed attempts per 15-minute window.
    fn default() -> Self {
        return Self::new(10, Duration::from_secs(DEFAULT_WINDOW_SECS));
    }
}

/// Production credential-gate preset: 100 failed attempts per 60-second window.
const PROD_MAX_ATTEMPTS: usize = 100;

/// Production credential-gate window: 60 seconds.
const PROD_WINDOW_SECS: u64 = 60;

impl InMemoryRateLimiter {
    /// Creates a new in-memory rate limiter on the system clock.
    ///
    /// * `max_attempts` — maximum failed attempts allowed within `window`.
    ///   Zero denies every attempt (fail-closed kill switch).
    /// * `window` — rolling time window for counting attempts. Zero prunes
    ///   every attempt immediately, so nothing is ever limited.
    #[must_use]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        return Self::with_clock(max_attempts, window, Arc::new(SystemTime::now));
    }

    /// Production credential-gate preset: 100 failed attempts per 60-second
    /// window.
    ///
    /// This is the single home for the prod numbers quoted by the hardening
    /// checklist (`docs/README.md`): turn it on for any credential endpoint
    /// facing the network. Tighter per-verb rules compose by constructing
    /// additional limiters with [`InMemoryRateLimiter::new`].
    #[must_use]
    pub fn prod() -> Self {
        return Self::new(PROD_MAX_ATTEMPTS, Duration::from_secs(PROD_WINDOW_SECS));
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
            max_tracked: DEFAULT_MAX_TRACKED_IDENTIFIERS,
            attempts: RwLock::new(BTreeMap::new()),
            now,
        };
    }

    /// Sets the ceiling on simultaneously tracked identifiers.
    ///
    /// A lapsed-identifier sweep runs when a new key needs room; if the sweep
    /// frees nothing, the least recently active entry is evicted. Bounding the
    /// map is what keeps a flood of distinct identifiers from growing it
    /// without limit. Values below one are treated as one.
    #[must_use]
    pub fn with_max_tracked(mut self, max_tracked: usize) -> Self {
        self.max_tracked = max_tracked.max(1);
        return self;
    }

    /// Number of identifiers currently tracked.
    ///
    /// Exposed for capacity monitoring: the map is bounded by
    /// [`with_max_tracked`](Self::with_max_tracked), and entries are reclaimed
    /// once their attempt window lapses.
    #[must_use]
    pub fn tracked_identifiers(&self) -> usize {
        return self.attempts.read().len();
    }

    /// Makes room for a new identifier when the map is at its ceiling.
    fn make_room(
        &self,
        attempts: &mut BTreeMap<String, Vec<SystemTime>>,
        identifier: &str,
        now: SystemTime,
    ) {
        if attempts.contains_key(identifier) || attempts.len() < self.max_tracked {
            return;
        }
        attempts.retain(|_, timestamps| {
            prune_expired(timestamps, now, self.window);
            return !timestamps.is_empty();
        });
        if attempts.len() < self.max_tracked {
            return;
        }
        let victim = attempts
            .iter()
            .filter_map(|(key, timestamps)| {
                return timestamps.last().map(|last| return (key.clone(), *last));
            })
            .min_by_key(|(_, last)| return *last)
            .map(|(key, _)| return key);
        if let Some(victim) = victim {
            attempts.remove(&victim);
        }
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn check(&self, identifier: &str) -> Result<(), AuthError> {
        let now = (self.now)();
        let limited = {
            let mut attempts = self.attempts.write();
            let limited = attempts.get_mut(identifier).is_some_and(|timestamps| {
                prune_expired(timestamps, now, self.window);
                return timestamps.len() >= self.max_attempts;
            });
            let lapsed = attempts
                .get(identifier)
                .is_some_and(|timestamps| return timestamps.is_empty());
            if lapsed {
                attempts.remove(identifier);
            }
            limited
        };
        if limited {
            return Err(AuthError::RateLimited);
        }
        return Ok(());
    }

    fn record_attempt(&self, identifier: &str) {
        let now = (self.now)();
        let mut attempts = self.attempts.write();
        self.make_room(&mut attempts, identifier, now);
        let timestamps = attempts.entry(identifier.to_string()).or_default();
        prune_expired(timestamps, now, self.window);
        timestamps.push(now);
        if timestamps.len() > self.max_attempts {
            let excess = timestamps.len() - self.max_attempts;
            timestamps.drain(..excess);
        }
        drop(attempts);
    }

    fn record_success(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        attempts.remove(identifier);
    }
}
