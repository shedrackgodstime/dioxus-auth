//! Login operation implementation.

use crate::engine::{AuthEngine, LoginOptions};
use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore};
use crate::user::AuthUser;

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    /// Authenticates a user by identifier and plaintext password.
    ///
    /// Constant-time defense: unknown-user login runs one Argon2 verification
    /// against the dummy hash, so miss and hit take indistinguishable time.
    ///
    /// Returns the authenticated user and the **raw wire session** (the id is
    /// sendable to the client; the store only ever sees its hash).
    ///
    /// # Errors
    /// Returns `AuthError::InvalidCredentials` for bad credentials,
    /// `AuthError::RateLimited` if the identifier is rate-limited, or a store
    /// or hasher error.
    #[must_use = "the session and authenticated user should be used"]
    pub fn login(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<(U::User, Session<U::Id>), AuthError> {
        return self.do_login(identifier, password, LoginOptions::default());
    }

    /// Authenticates a user with optional session metadata (IP, user agent).
    ///
    /// # Errors
    /// See [`AuthEngine::login`].
    #[must_use = "the authenticated user and session should be used"]
    pub fn login_with_options(
        &self,
        identifier: &str,
        password: &str,
        options: LoginOptions<'_>,
    ) -> Result<(U::User, Session<U::Id>), AuthError> {
        return self.do_login(identifier, password, options);
    }

    pub(crate) fn do_login(
        &self,
        identifier: &str,
        password: &str,
        options: LoginOptions<'_>,
    ) -> Result<(U::User, Session<U::Id>), AuthError> {
        let limiter_key = identifier.trim().to_lowercase();

        if let Some(limiter) = &self.rate_limiter {
            match limiter.check(&limiter_key) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
        }

        let user_entry = match self.users.find_by_identifier(identifier) {
            Ok(entry) => entry,
            Err(e) => return Err(e),
        };

        let (user, password_hash) = if let Some(entry) = user_entry {
            entry
        } else {
            if let Some(limiter) = &self.rate_limiter {
                limiter.record_attempt(&limiter_key);
            }
            drop(self.hasher.verify(password, &self.dummy_hash));
            return Err(AuthError::InvalidCredentials);
        };

        let is_valid = match self.hasher.verify(password, &password_hash) {
            Ok(valid) => valid,
            Err(e) => return Err(e),
        };
        if !is_valid {
            if let Some(limiter) = &self.rate_limiter {
                limiter.record_attempt(&limiter_key);
            }
            return Err(AuthError::InvalidCredentials);
        }

        let now = (self.now)();
        let expires_at = now + self.session_ttl_secs;
        let user_id = user.id();

        if self.single_active_session {
            match self.sessions.delete_user_sessions(&user_id) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
        } else if let Some(current_hash) = user.session_auth_hash() {
            // reason: rotate sessions minted under a previous credential
            // version so a password change revokes them at the next login
            // rather than only on first use (validate_session also drops
            // them lazily on use).
            let sessions = match self.sessions.list_user_sessions(&user_id) {
                Ok(list) => list,
                Err(e) => return Err(e),
            };
            for session in sessions {
                if let Some(session_hash) = session.auth_hash() {
                    if session_hash != current_hash {
                        if let Err(e) = self.sessions.delete_session(session.id()) {
                            return Err(e);
                        }
                    }
                }
            }
        }

        let raw_id = SessionId::generate();
        let storage_id = raw_id.hash_for_storage();
        let auth_hash = user.session_auth_hash().map(str::to_string);

        let mut storage_session =
            Session::new(storage_id, user_id.clone(), now, expires_at).with_last_active(now);
        if let Some(auth) = &auth_hash {
            storage_session = storage_session.with_auth_hash(auth.clone());
        }
        if let Some(ip) = options.ip_address() {
            storage_session = storage_session.with_ip_address(ip);
        }
        if let Some(ua) = options.user_agent() {
            storage_session = storage_session.with_user_agent(ua);
        }
        match self.sessions.save_session(storage_session) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }

        let mut wire_session = Session::new(raw_id, user_id, now, expires_at).with_last_active(now);
        if let Some(auth) = &auth_hash {
            wire_session = wire_session.with_auth_hash(auth.clone());
        }
        if let Some(ip) = options.ip_address() {
            wire_session = wire_session.with_ip_address(ip);
        }
        if let Some(ua) = options.user_agent() {
            wire_session = wire_session.with_user_agent(ua);
        }

        self.fire_on_sign_in(&user);
        if let Some(limiter) = &self.rate_limiter {
            limiter.record_success(&limiter_key);
        }
        return Ok((user, wire_session));
    }

    /// Whether an identifier (e.g. email or username) exists in the store.
    ///
    /// # Errors
    /// Returns a store error if the lookup fails.
    #[must_use = "the existence check must be used"]
    pub fn identifier_exists(&self, identifier: &str) -> Result<bool, AuthError> {
        match self.users.find_by_identifier(identifier) {
            Ok(Some(_)) => return Ok(true),
            Ok(None) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
}
