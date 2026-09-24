//! Logout and session revocation implementation.

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::CredentialStore;

impl<C, S> AuthEngine<C, S>
where
    C: CredentialStore,
    S: SessionStore<AuthId = C::AuthId>,
{
    /// Invalidates and revokes an active session (logout).
    ///
    /// The `session_id` is the raw wire token; the engine hashes it before
    /// touching the store. Malformed wire tokens are a cheap no-op rejection.
    /// The session row is deleted even when its subject row is already gone, so
    /// deleting a subject never strands orphan sessions behind.
    ///
    /// # Errors
    /// Returns a store error if the lookup or deletion fails.
    #[must_use = "sign-out must be acknowledged"]
    pub fn logout(&self, session_id: &SessionId) -> Result<(), AuthError> {
        let session = match self.find_wire_session(session_id) {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(()),
            Err(e) => return Err(e),
        };
        let subject = match self.store.find_subject(session.auth_id()) {
            Ok(subject) => subject,
            Err(e) => return Err(e),
        };
        match self.sessions.delete_session(session.id()) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        if let Some(subject) = subject {
            self.fire_on_sign_out(&subject);
        }
        return Ok(());
    }

    /// Revokes a single session by its raw wire token.
    ///
    /// Returns `Ok(true)` if the session existed and was revoked,
    /// `Ok(false)` if it did not exist. Malformed wire tokens report
    /// `Ok(false)` without any store access.
    ///
    /// # Errors
    /// Returns a store error if the lookup or deletion fails.
    #[must_use = "session revocation should not be silently ignored"]
    pub fn revoke_session(&self, session_id: &SessionId) -> Result<bool, AuthError> {
        let session = match self.find_wire_session(session_id) {
            Ok(session) => session,
            Err(e) => return Err(e),
        };
        let Some(session) = session else {
            return Ok(false);
        };
        match self.sessions.delete_session(session.id()) {
            Ok(()) => return Ok(true),
            Err(e) => return Err(e),
        };
    }

    /// Loads the stored session for a raw wire token.
    ///
    /// Malformed wire tokens yield `Ok(None)` without touching the store.
    fn find_wire_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<Session<C::AuthId>>, AuthError> {
        if !SessionId::is_valid_wire_format(session_id.as_str()) {
            return Ok(None);
        }
        let storage_id = session_id.hash_for_storage();
        return self.sessions.find_session(&storage_id);
    }

    /// Lists all sessions belonging to a subject.
    ///
    /// The read half of multi-session management ("log out other devices"):
    /// list here, revoke one session with [`revoke_session`](Self::revoke_session)
    /// or all of them with [`revoke_all_subject_sessions`](Self::revoke_all_subject_sessions).
    /// Order is store-defined; compare by id, never by position.
    ///
    /// # Errors
    /// Returns a store error if the listing fails.
    #[must_use = "the session list must be used"]
    pub fn list_subject_sessions(
        &self,
        auth_id: &C::AuthId,
    ) -> Result<Vec<Session<C::AuthId>>, AuthError> {
        return self.sessions.list_subject_sessions(auth_id);
    }

    /// Revokes all sessions belonging to a subject.
    ///
    /// # Errors
    /// Returns a store error if the deletion fails.
    #[must_use = "session revocation should not be silently ignored"]
    pub fn revoke_all_subject_sessions(&self, auth_id: &C::AuthId) -> Result<(), AuthError> {
        return self.sessions.delete_subject_sessions(auth_id);
    }
}
