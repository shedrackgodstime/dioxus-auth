//! Logout and session revocation implementation.

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore};

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    /// Invalidates and revokes an active session (logout).
    ///
    /// The `session_id` is the raw wire token; the engine hashes it before
    /// touching the store.
    ///
    /// # Errors
    /// Returns a store error if the lookup or deletion fails.
    pub fn logout(&self, session_id: &SessionId) -> Result<(), AuthError> {
        let storage_id = session_id.hash_for_storage();
        let session = match self.sessions.find_session(&storage_id) {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(()),
            Err(e) => return Err(e),
        };
        let user = match self.users.find_by_id(session.user_id()) {
            Ok(Some(user)) => user,
            Ok(None) => return Ok(()),
            Err(e) => return Err(e),
        };
        match self.sessions.delete_session(&storage_id) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        self.fire_on_sign_out(&user);
        Ok(())
    }

    /// Revokes a single session by its raw wire token.
    ///
    /// Returns `Ok(true)` if the session existed and was revoked,
    /// `Ok(false)` if it did not exist.
    ///
    /// # Errors
    /// Returns a store error if the lookup or deletion fails.
    #[must_use = "session revocation should not be silently ignored"]
    pub fn revoke_session(&self, session_id: &SessionId) -> Result<bool, AuthError> {
        let storage_id = session_id.hash_for_storage();
        let existed = match self.sessions.find_session(&storage_id) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => return Err(e),
        };
        if existed {
            match self.sessions.delete_session(&storage_id) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(existed)
    }

    /// Revokes all sessions belonging to a user.
    ///
    /// # Errors
    /// Returns a store error if the deletion fails.
    pub fn revoke_all_user_sessions(&self, user_id: &U::Id) -> Result<(), AuthError> {
        self.sessions.delete_user_sessions(user_id)
    }
}