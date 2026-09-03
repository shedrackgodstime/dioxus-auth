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
    /// Pre-computed Argon2-encoded hash of a constant dummy password.
    ///
    /// Used by [`AuthEngine::login`] when the identifier is not found, so that the
    /// verifier runs a real Argon2 verification on miss and the miss/hit paths take
    /// indistinguishable time. This closes the user-enumeration timing side-channel.
    pub(crate) dummy_hash: String,
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
    /// The `session_id` is the raw wire token (from cookie or bearer). The engine
    /// hashes it to its storage form before querying [`SessionStore`]. The store
    /// therefore only ever sees `sha256(raw)` and a leaked store yields no
    /// session-hijackable secrets.
    ///
    /// Checks if the session exists, is not expired, loads the corresponding user,
    /// and ensures `auth_hash` has not been invalidated (e.g. by a password change).
    /// Returns `Ok(Some(user))` on success, or `Ok(None)` if invalid/expired.
    pub async fn validate_session(&self, session_id: &SessionId) -> AuthResult<Option<U::User>> {
        let storage_id = session_id.hash_for_storage();
        let session = match self.sessions.find_session(&storage_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if session.is_expired_at(now) {
            let _ = self.sessions.delete_session(&storage_id).await;
            return Ok(None);
        }

        let user = match self.users.find_by_id(session.user_id()).await? {
            Some(u) => u,
            None => {
                let _ = self.sessions.delete_session(&storage_id).await;
                return Ok(None);
            }
        };

        // If both the user model and the active session define an auth_hash, ensure they match.
        // If the user changed their password, user.session_auth_hash() changes, invalidating old sessions.
        if let (Some(current_hash), Some(session_hash)) =
            (user.session_auth_hash(), session.auth_hash())
        {
            if current_hash != session_hash {
                let _ = self.sessions.delete_session(&storage_id).await;
                return Ok(None);
            }
        }

        Ok(Some(user))
    }

    /// Invalidate and revoke an active session (logout).
    ///
    /// The `session_id` is the raw wire token. The engine hashes it before
    /// touching the store.
    pub async fn logout(&self, session_id: &SessionId) -> AuthResult<()> {
        let storage_id = session_id.hash_for_storage();
        self.sessions.delete_session(&storage_id).await
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
    /// Implements timing attack mitigation by executing a real Argon2 password verification
    /// against a pre-computed dummy hash if the identifier is not found, ensuring
    /// indistinguishable response latency between the "user not found" and "wrong password"
    /// branches. The dummy hash is computed at builder time against the same configured
    /// hasher, so both branches perform one Argon2 invocation with the same cost.
    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
    ) -> AuthResult<(U::User, Session<<U::User as AuthUser>::Id>)> {
        let user_entry = self.users.find_by_identifier(identifier).await?;

        let (user, password_hash) = match user_entry {
            Some((u, hash)) => (Some(u), hash),
            None => {
                // Constant-time defense: run a real Argon2 verification against the
                // pre-computed dummy hash so the miss path is not distinguishable from
                // the hit path by timing.
                let _ = self.hasher.verify_password(password, &self.dummy_hash);
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

        let raw_id = SessionId::generate();
        let storage_id = raw_id.hash_for_storage();
        let auth_hash = user.session_auth_hash().map(str::to_string);

        // Build the storage record (keyed by hashed id).
        let mut storage_session = Session::new(storage_id, user.id(), now, expires_at);
        if let Some(ref h) = auth_hash {
            storage_session = storage_session.with_auth_hash(h.clone());
        }
        self.sessions.save_session(storage_session).await?;

        // Build the wire record returned to the caller (raw id, for the cookie).
        let mut wire_session = Session::new(raw_id, user.id(), now, expires_at);
        if let Some(h) = auth_hash {
            wire_session = wire_session.with_auth_hash(h);
        }
        Ok((user, wire_session))
    }
}
