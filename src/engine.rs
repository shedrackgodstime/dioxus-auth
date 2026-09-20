//! Central authentication flow orchestrator.

use std::fmt::Debug;
use std::sync::Arc;

use crate::builder::AuthEngineBuilder;
use crate::error::AuthError;
use crate::rate_limit::RateLimiter;
use crate::security::PasswordHasher;
use crate::store::{PasswordUserStore, SessionStore};

/// Options for [`AuthEngine::login_with_options`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LoginOptions<'a> {
    /// Client IP address for session activity tracking.
    pub ip_address: Option<&'a str>,
    /// Client user agent for session activity tracking.
    pub user_agent: Option<&'a str>,
}

/// Arc-wrapped user callback set by the builder.
pub(crate) type UserCallback<U> = Arc<dyn Fn(&U) + Send + Sync>;

/// Central authentication flow orchestrator.
///
/// Encapsulates credential verification with timing-attack mitigation,
/// CSPRNG session generation, session validation, expiration checks, and
/// session revocation.
///
/// Method implementations are split across the `login`, `logout`, `validate`,
/// and `hooks` modules and attached here as inherent methods.
#[derive(Clone)]
pub struct AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    pub(crate) users: Arc<U>,
    pub(crate) sessions: Arc<S>,
    pub(crate) hasher: Arc<dyn PasswordHasher>,
    pub(crate) session_ttl_secs: u64,
    pub(crate) idle_timeout_secs: Option<u64>,
    pub(crate) single_active_session: bool,
    pub(crate) on_sign_in: Option<UserCallback<U::User>>,
    pub(crate) on_sign_out: Option<UserCallback<U::User>>,
    pub(crate) on_session_validated: Option<UserCallback<U::User>>,
    pub(crate) rate_limiter: Option<Arc<dyn RateLimiter>>,
    /// Pre-computed Argon2-encoded hash of a constant dummy password.
    ///
    /// Used by [`AuthEngine::login`] when the identifier is not found, so the
    /// verifier runs a real Argon2 verification on miss and the miss/hit paths
    /// take indistinguishable time. This closes the user-enumeration timing
    /// side-channel.
    pub(crate) dummy_hash: String,
}

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    /// Creates a new [`AuthEngine`] with the default Argon2id hasher and
    /// 7-day session TTL.
    ///
    /// # Errors
    /// Returns `AuthError` if the default hasher cannot pre-compute the
    /// timing-defense dummy hash.
    pub fn new(users: Arc<U>, sessions: Arc<S>) -> Result<Self, AuthError> {
        Self::builder(users, sessions).build()
    }

    /// Starts configuring an [`AuthEngine`] via [`AuthEngineBuilder`].
    pub fn builder(users: Arc<U>, sessions: Arc<S>) -> AuthEngineBuilder<U, S> {
        AuthEngineBuilder::new(users, sessions)
    }

    /// Accesses the underlying user store.
    #[must_use]
    pub fn user_store(&self) -> &U {
        &self.users
    }

    /// Accesses the underlying session store.
    #[must_use]
    pub fn session_store(&self) -> &S {
        &self.sessions
    }

    /// Accesses the configured `PasswordHasher`.
    #[must_use]
    pub fn hasher(&self) -> &dyn PasswordHasher {
        &*self.hasher
    }

    /// Configured session time-to-live in seconds.
    #[must_use]
    pub const fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs
    }

    /// Configured idle timeout in seconds.
    #[must_use]
    pub const fn idle_timeout_secs(&self) -> Option<u64> {
        self.idle_timeout_secs
    }

    /// Whether single active session is enforced.
    #[must_use]
    pub const fn single_active_session(&self) -> bool {
        self.single_active_session
    }
}

/// Current UNIX timestamp in seconds.
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}