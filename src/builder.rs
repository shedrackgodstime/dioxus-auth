//! Builder for the authentication engine.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::engine::{AuthEngine, UserCallback, now_unix};
use crate::error::AuthError;
use crate::hash::Argon2Hasher;
use crate::rate_limit::RateLimiter;
use crate::security::PasswordHasher;
use crate::store::{SessionStore, UserStore};

/// Constant plaintext used to pre-compute the timing-defense dummy hash.
///
/// This string is never compared against a real user's password. It exists so
/// the Argon2 verifier runs on a real PHC-encoded hash when the identifier is
/// not found, closing the user-enumeration timing side-channel.
const DUMMY_PASSWORD: &str = "dioxus-auth-timing-defense-dummy-password-do-not-use";

/// Default session time-to-live: 7 days, in seconds.
const DEFAULT_SESSION_TTL_SECS: u64 = 60 * 60 * 24 * 7;

/// Fluent builder for constructing an [`AuthEngine`].
///
/// `Clone` clones the shared `Arc` handles and copies the plain scalar fields;
/// it does not clone the inner stores or hasher.
#[derive(Clone)]
#[must_use = "call `.build()` to construct the engine"]
pub struct AuthEngineBuilder<U, S>
where
    U: UserStore,
    S: SessionStore<Id = U::Id>,
{
    users: Arc<U>,
    sessions: Arc<S>,
    hasher: Option<Arc<dyn PasswordHasher>>,
    session_ttl_secs: u64,
    idle_timeout_secs: Option<u64>,
    single_active_session: bool,
    on_sign_in: Option<UserCallback<U::User>>,
    on_sign_out: Option<UserCallback<U::User>>,
    on_session_validated: Option<UserCallback<U::User>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl<U, S> fmt::Debug for AuthEngineBuilder<U, S>
where
    U: UserStore,
    S: SessionStore<Id = U::Id>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // reason: the clock is a closure; it is irrelevant for debugging and is
        // elided, and callbacks are reported as (un)set instead of rendered.
        let mut debug = f.debug_struct("AuthEngineBuilder");
        return crate::engine::shared_auth_debug_fields!(&mut debug, self)
            .field("on_sign_in", &self.on_sign_in.is_some())
            .field("on_sign_out", &self.on_sign_out.is_some())
            .field("on_session_validated", &self.on_session_validated.is_some())
            .field("rate_limiter", &self.rate_limiter)
            .field("now", &"<clock>")
            .finish();
    }
}

impl<U, S> AuthEngineBuilder<U, S>
where
    U: UserStore,
    S: SessionStore<Id = U::Id>,
{
    /// Creates a new builder with the given user and session stores.
    ///
    /// Custom setups reach this through
    /// [`AuthEngine::builder`](crate::engine::AuthEngine::builder), the
    /// documented entry point. Never call it directly.
    #[must_use = "a builder must eventually be built"]
    pub(super) fn new(users: Arc<U>, sessions: Arc<S>) -> Self {
        return Self {
            users,
            sessions,
            hasher: None,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            idle_timeout_secs: None,
            single_active_session: false,
            on_sign_in: None,
            on_sign_out: None,
            on_session_validated: None,
            rate_limiter: None,
            now: Arc::new(now_unix),
        };
    }

    /// Overrides the default hasher (defaults to [`Argon2Hasher`]).
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Some(Arc::new(hasher));
        return self;
    }

    /// Sets the session TTL.
    ///
    /// Prefer this over [`session_ttl_secs`](Self::session_ttl_secs); the
    /// `_secs` form exists for const contexts. Must be non-zero;
    /// [`build`](Self::build) rejects a zero TTL because it
    /// would mint instantly-dead sessions.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn session_ttl(mut self, duration: Duration) -> Self {
        self.session_ttl_secs = duration.as_secs();
        return self;
    }

    /// Sets the session TTL in seconds.
    ///
    /// Exists for const contexts; otherwise prefer
    /// [`session_ttl`](Self::session_ttl). Must be non-zero;
    /// [`build`](Self::build) rejects a zero TTL because it
    /// would mint instantly-dead sessions.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        return self;
    }

    /// Sets the idle timeout (max time without validated activity).
    ///
    /// Prefer this over [`idle_timeout_secs`](Self::idle_timeout_secs); the
    /// `_secs` form exists for const contexts. Must be non-zero when set;
    /// [`build`](Self::build) rejects a zero idle
    /// timeout because it would invalidate every session on next use.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn idle_timeout(mut self, duration: Duration) -> Self {
        self.idle_timeout_secs = Some(duration.as_secs());
        return self;
    }

    /// Sets the idle timeout in seconds.
    ///
    /// Exists for const contexts; otherwise prefer
    /// [`idle_timeout`](Self::idle_timeout). Must be non-zero when set;
    /// [`build`](Self::build) rejects a zero idle
    /// timeout because it would invalidate every session on next use.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = Some(secs);
        return self;
    }

    /// Enforces single active session per user on login.
    ///
    /// Process-local exactness: concurrent logins serialize through the
    /// engine's login lock, so exactly one session survives per login race.
    /// Distributed deployments need the same atomicity from their session
    /// store transaction. Without it, concurrent logins across processes can
    /// both survive.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn single_active_session(mut self, enabled: bool) -> Self {
        self.single_active_session = enabled;
        return self;
    }

    /// Hook called on successful sign-in.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn on_sign_in(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_in = Some(Arc::new(hook));
        return self;
    }

    /// Hook called on sign-out.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn on_sign_out(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_out = Some(Arc::new(hook));
        return self;
    }

    /// Hook called after successful session validation.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn on_session_validated(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_session_validated = Some(Arc::new(hook));
        return self;
    }

    /// Sets a custom rate limiter.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn rate_limiter(mut self, limiter: impl RateLimiter + 'static) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        return self;
    }

    /// Overrides the clock producing session timestamps.
    ///
    /// Defaults to the real system clock. Tests inject a deterministic clock to
    /// exercise idle-timeout and absolute-TTL expiry without sleeping.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn with_clock(mut self, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        return self;
    }

    /// Builds the authentication engine.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{AuthEngine, AuthUser, MemoryStore};
    /// # use std::sync::Arc;
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// # let store = Arc::new(MemoryStore::<User>::new());
    /// let engine = AuthEngine::builder(Arc::clone(&store), store)
    ///     .session_ttl_secs(3600)
    ///     .build()?;
    /// assert_eq!(engine.session_ttl_secs(), 3600);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `AuthError` if the timing-defense dummy hash cannot be computed.
    /// A zero session TTL or idle timeout also fails with `AuthError::Internal`:
    /// a zero lifetime mints instantly-dead sessions, which is never intended.
    #[must_use = "the constructed engine must be used"]
    pub fn build(self) -> Result<AuthEngine<U, S>, AuthError> {
        if self.session_ttl_secs == 0 {
            return Err(AuthError::Internal(String::from(
                "session TTL must be non-zero",
            )));
        }
        if self.idle_timeout_secs == Some(0) {
            return Err(AuthError::Internal(String::from(
                "idle timeout must be non-zero",
            )));
        }
        let hasher = self
            .hasher
            .unwrap_or_else(|| return Arc::new(Argon2Hasher::new()));
        let dummy_hash = match hasher.hash(DUMMY_PASSWORD) {
            Ok(hash) => hash,
            Err(e) => return Err(e),
        };
        return Ok(AuthEngine {
            users: self.users,
            sessions: self.sessions,
            hasher,
            session_ttl_secs: self.session_ttl_secs,
            idle_timeout_secs: self.idle_timeout_secs,
            single_active_session: self.single_active_session,
            on_sign_in: self.on_sign_in,
            on_sign_out: self.on_sign_out,
            on_session_validated: self.on_session_validated,
            rate_limiter: self.rate_limiter,
            dummy_hash,
            now: self.now,
            login_lock: Arc::new(parking_lot::Mutex::new(())),
        });
    }
}
