use std::sync::Arc;
use std::time::Duration;

use crate::engine::auth_engine::AuthEngine;
use crate::security::{Argon2Hasher, PasswordHasher, RateLimiter};
use crate::storage::{SessionStore, UserStore};
use crate::user::AuthUser;

/// Constant plaintext used to pre-compute the timing-defense dummy hash.
///
/// This string is never compared against a real user's password. It exists only so that
/// the Argon2 verifier runs on a real PHC-encoded hash when the identifier is not found,
/// closing the user-enumeration timing side-channel.
const DUMMY_PASSWORD: &str = "dioxus-auth-timing-defense-dummy-password-do-not-use";

/// Fluent builder for constructing an [`AuthEngine`].
pub struct AuthEngineBuilder<U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    users: Arc<U>,
    sessions: Arc<S>,
    hasher: Option<Arc<dyn PasswordHasher>>,
    session_ttl_secs: u64,
    sliding_window_secs: Option<u64>,
    rotate_tokens: bool,
    on_sign_in: Option<Arc<dyn Fn(&U::User) + Send + Sync>>,
    on_sign_out: Option<Arc<dyn Fn(&U::User) + Send + Sync>>,
    on_session_validated: Option<Arc<dyn Fn(&U::User) + Send + Sync>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
}

impl<U, S> AuthEngineBuilder<U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    /// Create a new builder with the given user and session stores.
    pub fn new(users: Arc<U>, sessions: Arc<S>) -> Self {
        Self {
            users,
            sessions,
            hasher: None,
            session_ttl_secs: 60 * 60 * 24 * 7, // 7 days
            sliding_window_secs: None,
            rotate_tokens: false,
            on_sign_in: None,
            on_sign_out: None,
            on_session_validated: None,
            rate_limiter: None,
        }
    }

    /// Override the default [`PasswordHasher`] (defaults to [`Argon2Hasher`]).
    pub fn hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Some(Arc::new(hasher));
        self
    }

    /// Set session TTL.
    pub fn session_ttl(mut self, duration: Duration) -> Self {
        self.session_ttl_secs = duration.as_secs();
        self
    }

    /// Set session TTL in seconds.
    pub fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        self
    }

    /// Enable sliding TTL.
    pub fn sliding_window(mut self, duration: Duration) -> Self {
        self.sliding_window_secs = Some(duration.as_secs());
        self
    }

    /// Enable sliding TTL in seconds.
    pub fn sliding_window_secs(mut self, secs: u64) -> Self {
        self.sliding_window_secs = Some(secs);
        self
    }

    /// Invalidate previous sessions on login.
    pub fn rotate_tokens(mut self, enabled: bool) -> Self {
        self.rotate_tokens = enabled;
        self
    }

    /// Hook fired after `login()`.
    pub fn on_sign_in(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_in = Some(Arc::new(hook));
        self
    }

    /// Hook fired after `logout()`.
    pub fn on_sign_out(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_out = Some(Arc::new(hook));
        self
    }

    /// Hook fired after `validate_session()`.
    pub fn on_session_validated(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_session_validated = Some(Arc::new(hook));
        self
    }

    /// Set a rate limiter to throttle login attempts per identifier.
    pub fn with_rate_limiter(mut self, limiter: impl RateLimiter + 'static) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// Build the configured [`AuthEngine`].
    ///
    /// Pre-computes a real Argon2 hash of the internal dummy password so the
    /// unknown-user timing defense runs an actual verification on miss.
    pub fn build(self) -> AuthEngine<U, S> {
        let hasher = self.hasher.unwrap_or_else(|| Arc::new(Argon2Hasher::new()));

        let dummy_hash = hasher
            .hash_password(DUMMY_PASSWORD)
            .expect("pre-computing dummy hash should not fail with a working hasher");

        AuthEngine {
            users: self.users,
            sessions: self.sessions,
            hasher,
            session_ttl_secs: self.session_ttl_secs,
            sliding_window_secs: self.sliding_window_secs,
            rotate_tokens: self.rotate_tokens,
            dummy_hash,
            on_sign_in: self.on_sign_in,
            on_sign_out: self.on_sign_out,
            on_session_validated: self.on_session_validated,
            rate_limiter: self.rate_limiter,
        }
    }
}
