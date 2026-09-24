//! Session validation implementation.

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{AuthSubject, CredentialStore, SubjectClaim};

impl<C, S> AuthEngine<C, S>
where
    C: CredentialStore,
    S: SessionStore<AuthId = C::AuthId>,
{
    /// Validates an incoming raw wire session id.
    ///
    /// The engine hashes the wire token to its storage form before querying
    /// the store, so the store only ever sees `sha256(raw)`.
    ///
    /// Malformed wire tokens (anything [`SessionId::is_valid_wire_format`]
    /// rejects) are a cheap rejection before any hashing or lookup.
    ///
    /// Checks that the session exists, is not expired, loads the corresponding
    /// subject, and ensures the `auth_hash` has not been invalidated (e.g. by
    /// a secret rotation). Idle timeout and sliding TTL are applied on success.
    ///
    /// Expiry is wall-clock: a clock that moves backwards can re-validate a
    /// session whose expiry passed unobserved. Expired sessions are deleted
    /// eagerly on use, so resurrection needs zero validations across the whole
    /// expired window. Deployments with hard revocation deadlines want a
    /// store with background sweeping, not lazy expiry alone.
    ///
    /// # Errors
    /// Returns a store error if a lookup or update fails.
    #[must_use = "the validated subject must be used"]
    pub fn validate_session(
        &self,
        session_id: &SessionId,
    ) -> Result<SubjectClaim<C::AuthId, C::AppRef>, AuthError> {
        if !SessionId::is_valid_wire_format(session_id.as_str()) {
            return Ok(None);
        }
        let storage_id = session_id.hash_for_storage();
        let session = match self.sessions.find_session(&storage_id) {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let now = (self.now)();

        if session.is_expired_at(now) {
            if let Err(e) = self.drop_session(&storage_id) {
                return Err(e);
            }
            return Ok(None);
        }

        let subject = match self.store.find_subject(session.auth_id()) {
            Ok(Some(subject)) => subject,
            Ok(None) => {
                if let Err(e) = self.drop_session(&storage_id) {
                    return Err(e);
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        if self.session_is_invalidated(&session, &subject, now) {
            if let Err(e) = self.drop_session(&storage_id) {
                return Err(e);
            }
            return Ok(None);
        }

        // reason: the storage record already carries `created + ttl` as its
        // expiry, so without an idle timeout the only per-validation write
        // (updating `last_active`) has no reader. Touching is therefore gated
        // on a configured idle timeout: the "cheap write" optimization.
        if self.idle_timeout_secs.is_some() {
            let new_expiry = session.created_at_unix() + self.session_ttl_secs;
            if let Err(e) = self
                .sessions
                .touch_session_if_present(&storage_id, new_expiry, now)
            {
                return Err(e);
            }
        }

        self.fire_on_session_validated(&subject);
        return Ok(Some(subject));
    }

    /// Validates a raw wire session id, returning the application key.
    ///
    /// The key-returning restore primitive: session proof without
    /// application resolution. Needs no `UserStore` and never touches app
    /// tables. Missing or expired sessions, and subjects without a linked
    /// key, all read as `Ok(None)` (fail closed); store outages propagate
    /// so transient failures never demote.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{AuthEngine, CredentialStore, DefaultStore, DefaultUserInput, SubjectStore};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// # let store = Arc::new(DefaultStore::new());
    /// # let engine = AuthEngine::new(Arc::clone(&store), Arc::clone(&store))?;
    /// # let hash = engine.hasher().hash("s3cret")?;
    /// # store.provision_subject(None, DefaultUserInput::new("alice"), "email", "alice", &hash)?;
    /// # let (_, session) = engine.login("alice", "s3cret")?;
    /// let app_key = engine.validate_key(session.id())?;
    /// assert_eq!(app_key, Some(1));
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns a store error if a lookup or update fails.
    #[must_use = "the application key must be used"]
    pub fn validate_key(&self, session_id: &SessionId) -> Result<Option<C::AppRef>, AuthError> {
        let subject = match self.validate_session(session_id) {
            Ok(subject) => subject,
            Err(error) => return Err(error),
        };
        let Some(subject) = subject else {
            return Ok(None);
        };
        return Ok(subject.app_ref);
    }

    /// Validates a session and resolves the application model in one call.
    ///
    /// Composes [`validate_key`](Self::validate_key) with a caller-supplied
    /// loader, same contract as [`login_user`](AuthEngine::login_user):
    /// plain caller code, any return type, synchronous inside this call.
    /// Missing sessions and unresolvable keys read as `Ok(None)`
    /// (definitive rejection); loader outages propagate. A session whose
    /// key no longer resolves is swept on the spot so zombies never
    /// accumulate, while outage paths never delete.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{AuthEngine, CredentialStore, DefaultStore, DefaultUserInput, SubjectStore};
    /// # use std::collections::HashMap;
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// # let store = Arc::new(DefaultStore::new());
    /// # let engine = AuthEngine::new(Arc::clone(&store), Arc::clone(&store))?;
    /// # let hash = engine.hasher().hash("s3cret")?;
    /// # store.provision_subject(None, DefaultUserInput::new("alice"), "email", "alice", &hash)?;
    /// # let (_, session) = engine.login("alice", "s3cret")?;
    /// # let directory = HashMap::from([(1u64, String::from("alice"))]);
    /// let name = engine.validate_user(session.id(), |key| {
    ///     return Ok(directory.get(key).cloned());
    /// })?;
    /// assert_eq!(name, Some(String::from("alice")));
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns a loader error as-is, or a store error if a lookup, touch,
    /// or sweep fails.
    #[must_use = "the resolved user must be used"]
    pub fn validate_user<U>(
        &self,
        session_id: &SessionId,
        loader: impl Fn(&C::AppRef) -> Result<Option<U>, AuthError>,
    ) -> Result<Option<U>, AuthError> {
        let app_key = match self.validate_key(session_id) {
            Ok(key) => key,
            Err(error) => return Err(error),
        };
        let Some(app_key) = app_key else {
            return Ok(None);
        };
        let user = match loader(&app_key) {
            Ok(user) => user,
            Err(error) => return Err(error),
        };
        let Some(user) = user else {
            // The key outlived its application row. Sweep the session so the
            // dead link cannot linger past its TTL; outages above already
            // returned before reaching here, so this delete never destroys
            // evidence of a transient failure.
            if let Err(error) = self.sessions.delete_session(&session_id.hash_for_storage()) {
                return Err(error);
            }
            return Ok(None);
        };
        return Ok(Some(user));
    }

    /// Whether a loaded, unexpired session must be dropped instead of accepted.
    ///
    /// Covers credential-version mismatch (e.g. after a secret rotation) and
    /// idle-timeout breach. Expiry is checked inline so a missing subject is
    /// never looked up for an already-dead session.
    fn session_is_invalidated(
        &self,
        session: &Session<C::AuthId>,
        subject: &AuthSubject<C::AuthId, C::AppRef>,
        now: u64,
    ) -> bool {
        if let (Some(current_hash), Some(session_hash)) =
            (subject.auth_hash.as_deref(), session.auth_hash())
        {
            if current_hash != session_hash {
                return true;
            }
        }

        if let Some(idle) = self.idle_timeout_secs {
            if let Some(last_active) = session.last_active_at_unix() {
                if now.saturating_sub(last_active) >= idle {
                    return true;
                }
            }
        }
        return false;
    }

    /// Deletes an invalid session, propagating store errors.
    fn drop_session(&self, id: &SessionId) -> Result<(), AuthError> {
        if let Err(e) = self.sessions.delete_session(id) {
            return Err(e);
        }
        return Ok(());
    }
}
