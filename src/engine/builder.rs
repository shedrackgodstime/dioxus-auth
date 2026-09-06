use std::sync::Arc;
use std::time::Duration;

use crate::engine::auth_engine::AuthEngine;
use crate::security::{Argon2Hasher, PasswordHasher};
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
        }
    }

    /// Override the default [`PasswordHasher`] (defaults to [`Argon2Hasher`]).
    pub fn hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Some(Arc::new(hasher));
        self
    }

    /// Configure the session time-to-live with a [`Duration`].
    pub fn session_ttl(mut self, duration: Duration) -> Self {
        self.session_ttl_secs = duration.as_secs();
        self
    }

    /// Configure the session time-to-live in seconds.
    pub fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        self
    }

    /// Configure sliding window for session expiry extension with a [`Duration`].
    ///
    /// When a session is accessed within the sliding window, its expiry is extended
    /// by `session_ttl`. For example, with a 7-day TTL and 1-day sliding window,
    /// a session accessed daily will stay alive indefinitely.
    pub fn sliding_window(mut self, duration: Duration) -> Self {
        self.sliding_window_secs = Some(duration.as_secs());
        self
    }

    /// Configure sliding window for session expiry extension in seconds.
    pub fn sliding_window_secs(mut self, secs: u64) -> Self {
        self.sliding_window_secs = Some(secs);
        self
    }

    /// Enable or disable token rotation on login.
    ///
    /// When enabled, calling [`AuthEngine::login`] invalidates all existing
    /// sessions for that user before creating a new session token.
    pub fn rotate_tokens(mut self, enabled: bool) -> Self {
        self.rotate_tokens = enabled;
        self
    }

    /// Register a hook that fires after a successful [`AuthEngine::login`].
    ///
    /// The hook receives a reference to the authenticated user. Panics inside the
    /// hook are caught and do not affect the login result.
    pub fn on_sign_in(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_in = Some(Arc::new(hook));
        self
    }

    /// Register a hook that fires after a successful [`AuthEngine::logout`].
    ///
    /// The hook receives a reference to the user whose session was revoked.
    /// Panics inside the hook are caught and do not affect the logout result.
    pub fn on_sign_out(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_sign_out = Some(Arc::new(hook));
        self
    }

    /// Register a hook that fires after a session is successfully validated
    /// by [`AuthEngine::validate_session`].
    ///
    /// The hook receives a reference to the authenticated user. Panics inside
    /// the hook are caught and do not affect the validation result.
    pub fn on_session_validated(mut self, hook: impl Fn(&U::User) + Send + Sync + 'static) -> Self {
        self.on_session_validated = Some(Arc::new(hook));
        self
    }

    /// Build the configured [`AuthEngine`].
    ///
    /// Pre-computes a real Argon2-encoded hash of [the internal dummy password] using the
    /// configured hasher, so that the unknown-user timing defense in
    /// [`AuthEngine::login`] runs an actual Argon2 verification on miss instead
    /// of short-circuiting on a malformed PHC string.
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
        }
    }
}
