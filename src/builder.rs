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
    pub fn new(users: Arc<U>, sessions: Arc<S>) -> Self {
        Self {
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
        }
    }

    /// Overrides the default hasher (defaults to [`Argon2Hasher`]).
    pub fn hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Some(Arc::new(hasher));
        self
    }

    /// Sets the session TTL.
    pub const fn session_ttl(mut self, duration: Duration) -> Self {
        self.session_ttl_secs = duration.as_secs();
        self
    }

    /// Sets the session TTL in seconds.
    pub const fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        self
    }

    /// Sets the idle timeout (max time without validated activity).
    pub const fn idle_timeout(mut self, duration: Duration) -> Self {
        self.idle_timeout_secs = Some(duration.as_secs());
        self
    }

    /// Sets the idle timeout in seconds.
    pub const fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = Some(secs);
        self
    }

    /// Enforces single active session per user on login.
    pub const fn single_active_session(mut self, enabled: bool) -> Self {
        self.single_active_session = enabled;
        self
    }

    /// Hook called on successful sign-in.
    pub fn on_sign_in(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_in = Some(Arc::new(hook));
        self
    }

    /// Hook called on sign-out.
    pub fn on_sign_out(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_out = Some(Arc::new(hook));
        self
    }

    /// Hook called after successful session validation.
    pub fn on_session_validated(
        mut self,
        hook: impl Fn(&U::User) + Send + Sync + 'static,
    ) -> Self {
        self.on_session_validated = Some(Arc::new(hook));
        self
    }

    /// Sets a custom rate limiter.
    pub fn rate_limiter(mut self, limiter: impl RateLimiter + 'static) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// Builds the authentication engine.
    ///
    /// # Errors
    /// Returns `AuthError` if the timing-defense dummy hash cannot be computed.
    pub fn build(self) -> Result<AuthEngine<U, S>, AuthError> {
        let hasher = match self.hasher {
            Some(hasher) => hasher,
            None => Arc::new(Argon2Hasher::new()),
        };
        let dummy_hash = match hasher.hash(DUMMY_PASSWORD) {
            Ok(hash) => hash,
            Err(e) => return Err(e),
        };
        Ok(AuthEngine {
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
        })
    }
}