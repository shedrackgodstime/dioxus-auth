//! Session validation implementation.

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore};
use crate::user::AuthUser;

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    /// Validates an incoming raw wire session id.
    ///
    /// The engine hashes the wire token to its storage form before querying
    /// the store, so the store only ever sees `sha256(raw)`.
    ///
    /// Checks that the session exists, is not expired, loads the corresponding
    /// user, and ensures the `auth_hash` has not been invalidated (e.g. by a
    /// password change). Idle timeout and sliding TTL are applied on success.
    ///
    /// # Errors
    /// Returns a store error if a lookup or update fails.
    pub fn validate_session(&self, session_id: &SessionId) -> Result<Option<U::User>, AuthError> {
        let storage_id = session_id.hash_for_storage();
        let session = match self.sessions.find_session(&storage_id) {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let now = crate::engine::now_unix();

        if session.is_expired_at(now) {
            return match self.sessions.delete_session(&storage_id) {
                Ok(()) => Ok(None),
                Err(e) => Err(e),
            };
        }

        let user = match self.users.find_by_id(session.user_id()) {
            Ok(Some(user)) => user,
            Ok(None) => {
                match self.sessions.delete_session(&storage_id) {
                    Ok(()) => {}
                    Err(e) => return Err(e),
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        if let (Some(current_hash), Some(session_hash)) = (
            user.session_auth_hash(),
            session.auth_hash(),
        ) {
            if current_hash != session_hash {
                match self.sessions.delete_session(&storage_id) {
                    Ok(()) => {}
                    Err(e) => return Err(e),
                }
                return Ok(None);
            }
        }

        if let Some(idle) = self.idle_timeout_secs {
            if let Some(last_active) = session.last_active_at_unix() {
                if now.saturating_sub(last_active) >= idle {
                    match self.sessions.delete_session(&storage_id) {
                        Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                    return Ok(None);
                }
            }
        }

        let new_expiry = session.created_at_unix() + self.session_ttl_secs;
        match self.sessions.touch_session_if_present(&storage_id, new_expiry, now) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }

        self.fire_on_session_validated(&user);
        Ok(Some(user))
    }
}