//! Login operation implementation.

use crate::engine::{AuthEngine, LoginOptions};
use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore};
use crate::user::AuthUser;

/// Canonical identifier key.
///
/// Trimmed and lowercased here, once, so spacing and case are display
/// variants of one throttle budget and one credential row rather than
/// separate keys. Every credential verb funnels its store and limiter calls
/// through this; stores compare byte-for-byte, never folding case or
/// whitespace themselves.
///
/// A free function, not a method: normalization belongs to no receiver.
/// Plain `pub` (not `pub(crate)`): the parent module is already `pub(crate)`,
/// which carries the restriction — spelling it again trips
/// `redundant_pub_crate`.
pub fn normalize_identifier(identifier: &str) -> String {
    return identifier.trim().to_lowercase();
}

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

    /// Applies the credential rate gate for one identifier.
    ///
    /// Normalizes here, once, so every verb shares one throttle window
    /// regardless of spacing or case and no caller has to remember to normalize.
    pub(crate) fn check_rate_limit(&self, identifier: &str) -> Result<(), AuthError> {
        if let Some(limiter) = &self.rate_limiter {
            return limiter.check(&normalize_identifier(identifier));
        }
        return Ok(());
    }

    /// Records a failed credential attempt for one identifier.
    pub(crate) fn record_rate_limit_failure(&self, identifier: &str) {
        if let Some(limiter) = &self.rate_limiter {
            limiter.record_attempt(&normalize_identifier(identifier));
        }
    }

    /// Clears the throttle budget for one identifier after proven knowledge.
    pub(crate) fn record_rate_limit_success(&self, identifier: &str) {
        if let Some(limiter) = &self.rate_limiter {
            limiter.record_success(&normalize_identifier(identifier));
        }
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
        match self.check_rate_limit(identifier) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        return self.authenticate_user(identifier, password);
    }

    pub(crate) fn do_login(
        &self,
        identifier: &str,
        password: &str,
        options: LoginOptions<'_>,
    ) -> Result<(U::User, Session<U::Id>), AuthError> {
        let user = match self.verify_password(identifier, password) {
            Ok(user) => user,
            Err(e) => return Err(e),
        };

        let now = (self.now)();
        let expires_at = now + self.session_ttl_secs;
        let user_id = user.id();
        let auth_hash = user.session_auth_hash().map(str::to_string);

        // reason: the guard is scoped to save + rotation only. Holding it
        // across the sign-in hook below would deadlock hooks that call back
        // into the engine (the lock is non-reentrant); releasing it here keeps
        // the write window atomic without extending the critical section into
        // user code. ID generation stays outside: it needs no sharing.
        let raw_id = SessionId::generate();
        let storage_id = raw_id.hash_for_storage();
        let storage_session = Self::apply_session_options(
            Session::new(storage_id.clone(), user_id.clone(), now, expires_at)
                .with_last_active(now),
            auth_hash.as_deref(),
            &options,
        );
        {
            let _guard = self.login_lock.lock();
            // Save before rotation: if the save fails, prior sessions are
            // untouched and the login reports the store error with nothing
            // lost. Rotation spares the just-saved session, so a rotation
            // failure leaves a valid-but-unreturned session that the next
            // login's rotation sweeps — failures self-heal on retry instead
            // of destroying live sessions.
            match self.sessions.save_session(storage_session) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            match self.rotate_stale_sessions(&user_id, auth_hash.as_deref(), &storage_id) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
        }

        let wire_session = Self::apply_session_options(
            Session::new(raw_id, user_id, now, expires_at).with_last_active(now),
            auth_hash.as_deref(),
            &options,
        );

        self.fire_on_sign_in(&user);
        self.record_rate_limit_success(identifier);
        return Ok((user, wire_session));
    }

    /// Runs one verifier pass against the dummy hash.
    ///
    /// Credential paths that must not reveal identifier state burn the same
    /// verifier work the unknown-identifier miss path runs; the outcome is
    /// discarded and the caller returns `InvalidCredentials` either way.
    pub(crate) fn dummy_verify(&self, password: &str) {
        let _burned = self.hasher.verify(password, &self.dummy_hash).is_ok();
    }

    /// Resolves and verifies the user for an identifier/password pair.
    ///
    /// Constant-time defense: unknown-user login runs one Argon2 verification
    /// against the dummy hash, so miss and hit take indistinguishable time.
    fn authenticate_user(&self, identifier: &str, password: &str) -> Result<U::User, AuthError> {
        let normalized = normalize_identifier(identifier);
        let user_entry = match self.users.find_by_identifier(&normalized) {
            Ok(entry) => entry,
            Err(e) => return Err(e),
        };

        let (user, password_hash) = if let Some(entry) = user_entry {
            entry
        } else {
            self.record_rate_limit_failure(&normalized);
            self.dummy_verify(password);
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
            self.record_rate_limit_failure(&normalized);
            return Err(AuthError::InvalidCredentials);
        }
        return Ok(user);
    }

    /// Deletes sessions superseded by the current credential state, sparing
    /// the just-saved session.
    ///
    /// With single-active-session enforcement every other existing session
    /// goes; otherwise only sessions minted under a rotated credential version
    /// are removed, so a password change revokes them at the next login rather
    /// than only on first use (`validate_session` also drops them lazily).
    /// `spare` is the storage-form id saved moments ago in the same locked
    /// window: rotation must never reap the session it just made room for.
    fn rotate_stale_sessions(
        &self,
        user_id: &U::Id,
        current_hash: Option<&str>,
        spare: &SessionId,
    ) -> Result<(), AuthError> {
        if self.single_active_session {
            let sessions = match self.sessions.list_user_sessions(user_id) {
                Ok(sessions) => sessions,
                Err(e) => return Err(e),
            };
            for session in sessions {
                if session.id() != spare {
                    if let Err(e) = self.sessions.delete_session(session.id()) {
                        return Err(e);
                    }
                }
            }
            return Ok(());
        }
        let Some(current_hash) = current_hash else {
            return Ok(());
        };
        let sessions = match self.sessions.list_user_sessions(user_id) {
            Ok(sessions) => sessions,
            Err(e) => return Err(e),
        };
        for session in sessions {
            if session.id() == spare {
                continue;
            }
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
}
