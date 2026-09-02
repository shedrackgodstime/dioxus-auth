use std::sync::Arc;

use crate::engine::builder::AuthEngineBuilder;
use crate::error::{AuthError, AuthResult};
use crate::security::PasswordHasher;
use crate::session::{Session, SessionId};
use crate::storage::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

/// Central authentication flow orchestrator.
///
/// Encapsulates credential verification with timing-attack mitigation,
/// CSPRNG session generation, session validation, expiration checks, and session revocation.
#[derive(Clone)]
pub struct AuthEngine<U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    pub(crate) users: Arc<U>,
    pub(crate) sessions: Arc<S>,
    pub(crate) hasher: Arc<dyn PasswordHasher>,
    pub(crate) session_ttl_secs: u64,
}

impl<U, S> AuthEngine<U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    /// Create a new [`AuthEngine`] with default Argon2id hasher and 7-day session TTL.
    pub fn new(users: Arc<U>, sessions: Arc<S>) -> Self {
        Self::builder(users, sessions).build()
    }

    /// Start configuring an [`AuthEngine`] via [`AuthEngineBuilder`].
    pub fn builder(users: Arc<U>, sessions: Arc<S>) -> AuthEngineBuilder<U, S> {
        AuthEngineBuilder::new(users, sessions)
    }

    /// Access the underlying `UserStore`.
    pub fn user_store(&self) -> &U {
        &self.users
    }

    /// Access the underlying `SessionStore`.
    pub fn session_store(&self) -> &S {
        &self.sessions
    }

    /// Access the configured `PasswordHasher`.
    pub fn hasher(&self) -> &dyn PasswordHasher {
        &*self.hasher
    }

    /// Configured session time-to-live in seconds.
    pub fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs
    }

    /// Validate an incoming session ID.
    ///
    /// Checks if the session exists, is not expired, loads the corresponding user,
    /// and ensures `auth_hash` has not been invalidated (e.g. by a password change).
    /// Returns `Ok(Some(user))` on success, or `Ok(None)` if invalid/expired.
    pub async fn validate_session(&self, session_id: &SessionId) -> AuthResult<Option<U::User>> {
        let session = match self.sessions.find_session(session_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if session.is_expired_at(now) {
            let _ = self.sessions.delete_session(session_id).await;
            return Ok(None);
        }

        let user = match self.users.find_by_id(session.user_id()).await? {
            Some(u) => u,
            None => {
                let _ = self.sessions.delete_session(session_id).await;
                return Ok(None);
            }
        };

        // If both the user model and the active session define an auth_hash, ensure they match.
        // If the user changed their password, user.session_auth_hash() changes, invalidating old sessions.
        if let (Some(current_hash), Some(session_hash)) =
            (user.session_auth_hash(), session.auth_hash())
        {
            if current_hash != session_hash {
                let _ = self.sessions.delete_session(session_id).await;
                return Ok(None);
            }
        }

        Ok(Some(user))
    }

    /// Invalidate and revoke an active session (logout).
    pub async fn logout(&self, session_id: &SessionId) -> AuthResult<()> {
        self.sessions.delete_session(session_id).await
    }

    /// Invalidate all sessions for a specific user ID.
    pub async fn revoke_all_user_sessions(
        &self,
        user_id: &<U::User as AuthUser>::Id,
    ) -> AuthResult<()> {
        self.sessions.delete_user_sessions(user_id).await
    }
}

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    /// Authenticate a user by identifier (e.g. email or username) and plaintext password.
    ///
    /// Implements timing attack mitigation by executing a dummy Argon2 password verification
    /// if the identifier is not found, ensuring indistinguishable response latency.
    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
    ) -> AuthResult<(U::User, Session<<U::User as AuthUser>::Id>)> {
        let user_entry = self.users.find_by_identifier(identifier).await?;

        let (user, password_hash) = match user_entry {
            Some((u, hash)) => (Some(u), hash),
            None => {
                // Constant-time defense: run a dummy Argon2 verification when user is not found
                // to prevent attacker from enumerating valid usernames by measuring response latency.
                let dummy_hash =
                    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$dummyhashdummyhashdummyhash";
                let _ = self.hasher.verify_password(password, dummy_hash);
                return Err(AuthError::Unauthenticated);
            }
        };

        let is_valid = self.hasher.verify_password(password, &password_hash)?;
        if !is_valid {
            return Err(AuthError::Unauthenticated);
        }

        let user = user.expect("user exists");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = now + self.session_ttl_secs;

        let session_id = SessionId::generate();
        let mut session = Session::new(session_id, user.id(), now, expires_at);
        if let Some(auth_hash) = user.session_auth_hash() {
            session = session.with_auth_hash(auth_hash);
        }

        self.sessions.save_session(session.clone()).await?;
        Ok((user, session))
    }
}
