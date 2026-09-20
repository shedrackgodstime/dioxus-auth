//! Builder for the authentication engine.

use std::sync::Arc;
use std::time::Duration;

use crate::engine::{AuthEngine, UserCallback};
use crate::error::AuthError;
use crate::hash::Argon2Hasher;
use crate::rate_limit::RateLimiter;
use crate::security::PasswordHasher;
use crate::store::{PasswordUserStore, SessionStore};

/// Constant plaintext used to pre-compute the timing-defense dummy hash.
///
/// This string is never compared against a real user's password. It exists so
/// the Argon2 verifier runs on a real PHC-encoded hash when the identifier is
/// not found, closing the user-enumeration timing side-channel.
const DUMMY_PASSWORD: &str = "dioxus-auth-timing-defense-dummy-password-do-not-use";

/// Fluent builder for constructing an [`AuthEngine`].
///
/// `Clone` clones the shared `Arc` handles and copies the plain scalar fields;
/// it does not clone the inner stores or hasher.
#[derive(Clone)]
#[must_use = "call `.build()` to construct the engine"]
pub struct AuthEngineBuilder<U, S>
where
    U: PasswordUserStore,
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
}

impl<U, S> AuthEngineBuilder<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    /// Creates a new builder with the given user and session stores.
    #[must_use = "a builder must eventually be built"]
    pub fn new(users: Arc<U>, sessions: Arc<S>) -> Self {
        return Self {
            users,
            sessions,
            hasher: None,
            session_ttl_secs: 60 * 60 * 24 * 7,
            idle_timeout_secs: None,
            single_active_session: false,
            on_sign_in: None,
            on_sign_out: None,
            on_session_validated: None,
            rate_limiter: None,
        };
    }

    /// Overrides the default hasher (defaults to [`Argon2Hasher`]).
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub fn hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Some(Arc::new(hasher));
        return self;
    }

    /// Sets the session TTL.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn session_ttl(mut self, duration: Duration) -> Self {
        self.session_ttl_secs = duration.as_secs();
        return self;
    }

    /// Sets the session TTL in seconds.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        return self;
    }

    /// Sets the idle timeout (max time without validated activity).
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn idle_timeout(mut self, duration: Duration) -> Self {
        self.idle_timeout_secs = Some(duration.as_secs());
        return self;
    }

    /// Sets the idle timeout in seconds.
    #[must_use = "chained builder configuration is discarded if not fed into `.build()`"]
    pub const fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = Some(secs);
        return self;
    }

    /// Enforces single active session per user on login.
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

    /// Builds the authentication engine.
    ///
    /// # Errors
    /// Returns `AuthError` if the timing-defense dummy hash cannot be computed.
    #[must_use = "the constructed engine must be used"]
    pub fn build(self) -> Result<AuthEngine<U, S>, AuthError> {
        let hasher = match self.hasher {
            Some(hasher) => hasher,
            None => Arc::new(Argon2Hasher::new()),
        };
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
        });
    }
}
