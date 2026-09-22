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

    /// Verifies an identifier/password pair without minting a session.
    ///
    /// Same gate check and oracle semantics as [`AuthEngine::login`], minus
    /// the session, rotation, hooks, and success accounting. Callers record
    /// success through the limiter after their own work completes, so a
    /// failed store write never resets the counter early. Used by
    /// credential-management verbs that must prove knowledge without
    /// signing in.
    pub(crate) fn verify_password(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<U::User, AuthError> {
        let limiter_key = identifier.trim().to_lowercase();
        if let Some(limiter) = &self.rate_limiter {
            match limiter.check(&limiter_key) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
        }
        return self.authenticate_user(identifier, password, &limiter_key);
    }

    pub(crate) fn do_login(
        &self,
        identifier: &str,
        password: &str,
        options: LoginOptions<'_>,
    ) -> Result<(U::User, Session<U::Id>), AuthError> {
        let limiter_key = identifier.trim().to_lowercase();

        let user = match self.verify_password(identifier, password) {
            Ok(user) => user,
            Err(e) => return Err(e),
        };

        let now = (self.now)();
        let expires_at = now + self.session_ttl_secs;
        let user_id = user.id();
        let auth_hash = user.session_auth_hash().map(str::to_string);

        match self.rotate_stale_sessions(&user_id, auth_hash.as_deref()) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }

        let raw_id = SessionId::generate();
        let storage_id = raw_id.hash_for_storage();
        let storage_session = Self::apply_session_options(
            Session::new(storage_id, user_id.clone(), now, expires_at).with_last_active(now),
            auth_hash.as_deref(),
            &options,
        );
        match self.sessions.save_session(storage_session) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }

        let wire_session = Self::apply_session_options(
            Session::new(raw_id, user_id, now, expires_at).with_last_active(now),
            auth_hash.as_deref(),
            &options,
        );

        self.fire_on_sign_in(&user);
        if let Some(limiter) = &self.rate_limiter {
            limiter.record_success(&limiter_key);
        }
        return Ok((user, wire_session));
    }

    /// Resolves and verifies the user for an identifier/password pair.
    ///
    /// Constant-time defense: unknown-user login runs one Argon2 verification
    /// against the dummy hash, so miss and hit take indistinguishable time.
    fn authenticate_user(
        &self,
        identifier: &str,
        password: &str,
        limiter_key: &str,
    ) -> Result<U::User, AuthError> {
        let user_entry = match self.users.find_by_identifier(identifier) {
            Ok(entry) => entry,
            Err(e) => return Err(e),
        };

        let (user, password_hash) = if let Some(entry) = user_entry {
            entry
        } else {
            if let Some(limiter) = &self.rate_limiter {
                limiter.record_attempt(limiter_key);
            }
            // reason: the dummy verification exists only to burn verifier time
            // on unknown identifiers; its outcome is irrelevant, so both arms
            // fall through to `InvalidCredentials` without branching on it.
            let _burned = self.hasher.verify(password, &self.dummy_hash).is_ok();
            return Err(AuthError::InvalidCredentials);
        };

        // reason: a malformed stored hash must not be distinguishable from a
        // wrong password through this error channel — a distinct, fast
        // `PasswordHashError` would confirm "identifier exists and its stored
        // hash is garbage" to an attacker probing login. `unwrap_or(false)`
        // collapses it to a miss here; the hasher's `Err` channel stays
        // available to direct callers (account setup, admin tooling) where no
        // oracle exists.
        let is_valid = self
            .hasher
            .verify(password, &password_hash)
            .unwrap_or(false);
        if !is_valid {
            if let Some(limiter) = &self.rate_limiter {
                limiter.record_attempt(limiter_key);
            }
            return Err(AuthError::InvalidCredentials);
        }
        return Ok(user);
    }

    /// Deletes sessions superseded by the current credential state.
    ///
    /// With single-active-session enforcement every existing session goes;
    /// otherwise only sessions minted under a rotated credential version are
    /// removed, so a password change revokes them at the next login rather
    /// than only on first use (`validate_session` also drops them lazily).
    fn rotate_stale_sessions(
        &self,
        user_id: &U::Id,
        current_hash: Option<&str>,
    ) -> Result<(), AuthError> {
        if self.single_active_session {
            return match self.sessions.delete_user_sessions(user_id) {
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            };
        }
        let Some(current_hash) = current_hash else {
            return Ok(());
        };
        let sessions = match self.sessions.list_user_sessions(user_id) {
            Ok(sessions) => sessions,
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
        return Ok(());
    }

    /// Attaches the credential version and request metadata to a session.
    fn apply_session_options(
        session: Session<U::Id>,
        auth_hash: Option<&str>,
        options: &LoginOptions<'_>,
    ) -> Session<U::Id> {
        let mut session = session;
        if let Some(auth) = auth_hash {
            session = session.with_auth_hash(auth);
        }
        if let Some(ip) = options.ip_address() {
            session = session.with_ip_address(ip);
        }
        if let Some(user_agent) = options.user_agent() {
            session = session.with_user_agent(user_agent);
        }
        return session;
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
