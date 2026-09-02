use std::sync::Arc;
use std::time::Duration;

use crate::engine::auth_engine::AuthEngine;
use crate::security::{Argon2Hasher, PasswordHasher};
use crate::storage::{SessionStore, UserStore};
use crate::user::AuthUser;

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

    /// Build the configured [`AuthEngine`].
    pub fn build(self) -> AuthEngine<U, S> {
        let hasher = self.hasher.unwrap_or_else(|| Arc::new(Argon2Hasher::new()));

        AuthEngine {
            users: self.users,
            sessions: self.sessions,
            hasher,
            session_ttl_secs: self.session_ttl_secs,
        }
    }
}
