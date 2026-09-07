use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use crate::engine::builder::AuthEngineBuilder;
use crate::error::{AuthError, AuthResult};
use crate::security::{PasswordHasher, RateLimiter};
use crate::session::{Session, SessionId};
use crate::storage::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

/// Options for [`AuthEngine::login_with_options`].
#[derive(Debug, Clone, Default)]
pub struct LoginOptions<'a> {
    /// Client IP address for session activity tracking.
    pub ip_address: Option<&'a str>,
    /// Client user agent for session activity tracking.
    pub user_agent: Option<&'a str>,
}

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
    pub(crate) sliding_window_secs: Option<u64>,
    pub(crate) rotate_tokens: bool,
    pub(crate) on_sign_in: Option<Arc<dyn Fn(&U::User) + Send + Sync>>,
    pub(crate) on_sign_out: Option<Arc<dyn Fn(&U::User) + Send + Sync>>,
    pub(crate) on_session_validated: Option<Arc<dyn Fn(&U::User) + Send + Sync>>,
    pub(crate) rate_limiter: Option<Arc<dyn RateLimiter>>,
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

        if let (Some(current_hash), Some(session_hash)) =
            (user.session_auth_hash(), session.auth_hash())
        {
            if current_hash != session_hash {
                let _ = self.sessions.delete_session(&storage_id).await;
                return Ok(None);
            }
        }

        if let Some(window) = self.sliding_window_secs {
            let time_since_creation = now - session.created_at_unix();
            if time_since_creation < window {
                let extended = session.extend_expiry(now, self.session_ttl_secs);
                let _ = self.sessions.save_session(extended).await;
            }
        }

        self.fire_on_session_validated(&user);
        Ok(Some(user))
    }

    /// Invalidate and revoke an active session (logout).
    ///
    /// The `session_id` is the raw wire token. The engine hashes it before
    /// touching the store.
    pub async fn logout(&self, session_id: &SessionId) -> AuthResult<()> {
        let storage_id = session_id.hash_for_storage();
        if let Some(session) = self.sessions.find_session(&storage_id).await? {
            if let Some(user) = self.users.find_by_id(session.user_id()).await? {
                self.sessions.delete_session(&storage_id).await?;
                self.fire_on_sign_out(&user);
            }
        }
        Ok(())
    }

    /// Invalidate all sessions for a specific user ID.
    pub async fn revoke_all_user_sessions(
        &self,
        user_id: &<U::User as AuthUser>::Id,
    ) -> AuthResult<()> {
        self.sessions.delete_user_sessions(user_id).await
    }

    /// Configured sliding window in seconds, if any.
    pub fn sliding_window_secs(&self) -> Option<u64> {
        self.sliding_window_secs
    }

    /// Whether token rotation is enabled on login.
    pub fn rotate_tokens(&self) -> bool {
        self.rotate_tokens
    }

    /// Access the pre-computed dummy Argon2 hash used for timing defense on unknown-user login.
    #[cfg(any(test, doc))]
    pub(crate) fn dummy_hash(&self) -> &str {
        &self.dummy_hash
    }

    /// List all active sessions for a specific user ID.
    pub async fn list_user_sessions(
        &self,
        user_id: &<U::User as AuthUser>::Id,
    ) -> AuthResult<Vec<Session<<U::User as AuthUser>::Id>>> {
        self.sessions.list_user_sessions(user_id).await
    }

    /// Revoke a single session by its raw wire token.
    ///
    /// Returns `Ok(true)` if the session existed and was revoked, `Ok(false)` if it did not exist.
    #[must_use = "session revocation should not be silently ignored"]
    pub async fn revoke_session(&self, session_id: &SessionId) -> AuthResult<bool> {
        let storage_id = session_id.hash_for_storage();
        let existed = self.sessions.find_session(&storage_id).await?.is_some();
        if existed {
            self.sessions.delete_session(&storage_id).await?;
        }
        Ok(existed)
    }

    fn fire_hook(&self, hook: Option<&Arc<dyn Fn(&U::User) + Send + Sync>>, user: &U::User) {
        if let Some(hook) = hook {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| hook(user)));
        }
    }

    fn fire_on_sign_in(&self, user: &U::User) {
        self.fire_hook(self.on_sign_in.as_ref(), user);
    }

    fn fire_on_sign_out(&self, user: &U::User) {
        self.fire_hook(self.on_sign_out.as_ref(), user);
    }

    fn fire_on_session_validated(&self, user: &U::User) {
        self.fire_hook(self.on_session_validated.as_ref(), user);
    }
}

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    /// Authenticate a user by identifier and plaintext password.
    ///
    /// Constant-time defense: unknown-user login runs one Argon2 verification
    /// against the dummy hash, so miss and hit take indistinguishable time.
    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
    ) -> AuthResult<(U::User, Session<<U::User as AuthUser>::Id>)> {
        self.do_login(identifier, password, LoginOptions::default())
            .await
    }

    /// Authenticate a user with optional session metadata (IP address, user agent).
    #[must_use = "the authenticated user and session should be used"]
    pub async fn login_with_options(
        &self,
        identifier: &str,
        password: &str,
        options: LoginOptions<'_>,
    ) -> AuthResult<(U::User, Session<<U::User as AuthUser>::Id>)> {
        self.do_login(identifier, password, options).await
    }

    async fn do_login(
        &self,
        identifier: &str,
        password: &str,
        options: LoginOptions<'_>,
    ) -> AuthResult<(U::User, Session<<U::User as AuthUser>::Id>)> {
        if let Some(limiter) = &self.rate_limiter {
            limiter.check(identifier)?;
        }

        let user_entry = self.users.find_by_identifier(identifier).await?;

        let (user, password_hash) = match user_entry {
            Some((u, hash)) => (Some(u), hash),
            None => {
                if let Some(limiter) = &self.rate_limiter {
                    limiter.record_attempt(identifier);
                }
                let _ = self.hasher.verify_password(password, &self.dummy_hash);
                return Err(AuthError::Unauthenticated);
            }
        };

        let is_valid = self.hasher.verify_password(password, &password_hash)?;
        if !is_valid {
            if let Some(limiter) = &self.rate_limiter {
                limiter.record_attempt(identifier);
            }
            return Err(AuthError::Unauthenticated);
        }

        let user = user.expect("user exists");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = now + self.session_ttl_secs;

        if self.rotate_tokens {
            let _ = self.sessions.delete_user_sessions(&user.id()).await;
        }

        let raw_id = SessionId::generate();
        let storage_id = raw_id.hash_for_storage();
        let auth_hash = user.session_auth_hash().map(str::to_string);

        let mut storage_session = Session::new(storage_id, user.id(), now, expires_at);
        if let Some(ref h) = auth_hash {
            storage_session = storage_session.with_auth_hash(h.clone());
        }
        if let Some(ip) = options.ip_address {
            storage_session = storage_session.with_ip_address(ip);
        }
        if let Some(ua) = options.user_agent {
            storage_session = storage_session.with_user_agent(ua);
        }
        self.sessions.save_session(storage_session).await?;

        let mut wire_session = Session::new(raw_id, user.id(), now, expires_at);
        if let Some(h) = auth_hash {
            wire_session = wire_session.with_auth_hash(h);
        }
        self.fire_on_sign_in(&user);
        if let Some(limiter) = &self.rate_limiter {
            limiter.record_success(identifier);
        }
        Ok((user, wire_session))
    }

    /// Check whether an identifier (e.g. email or username) already exists in the store.
    ///
    /// Returns `Ok(true)` if a user with the given identifier was found,
    /// `Ok(false)` if not, or an error if the store query failed.
    pub async fn identifier_exists(&self, identifier: &str) -> AuthResult<bool> {
        self.users
            .find_by_identifier(identifier)
            .await
            .map(|opt| opt.is_some())
    }
}
