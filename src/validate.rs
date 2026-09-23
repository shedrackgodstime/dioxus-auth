//! Session validation implementation.

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::{SessionStore, UserStore};
use crate::user::AuthUser;

impl<U, S> AuthEngine<U, S>
where
    U: UserStore,
    S: SessionStore<Id = U::Id>,
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
    /// user, and ensures the `auth_hash` has not been invalidated (e.g. by a
    /// password change). Idle timeout and sliding TTL are applied on success.
    ///
    /// Expiry is wall-clock: a clock that moves backwards can re-validate a
    /// session whose expiry passed unobserved. Expired sessions are deleted
    /// eagerly on use, so resurrection needs zero validations across the whole
    /// expired window. Deployments with hard revocation deadlines want a
    /// store with background sweeping, not lazy expiry alone.
    ///
    /// # Errors
    /// Returns a store error if a lookup or update fails.
    #[must_use = "the validated user must be used"]
    pub fn validate_session(&self, session_id: &SessionId) -> Result<Option<U::User>, AuthError> {
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

        let user = match self.users.find_by_id(session.user_id()) {
            Ok(Some(user)) => user,
            Ok(None) => {
                if let Err(e) = self.drop_session(&storage_id) {
                    return Err(e);
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        if self.session_is_invalidated(&session, &user, now) {
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

        self.fire_on_session_validated(&user);
        return Ok(Some(user));
    }

    /// Whether a loaded, unexpired session must be dropped instead of accepted.
    ///
    /// Covers credential-version mismatch (e.g. after a password change) and
    /// idle-timeout breach. Expiry is checked inline so a missing user is
    /// never looked up for an already-dead session.
    fn session_is_invalidated(&self, session: &Session<U::Id>, user: &U::User, now: u64) -> bool {
        if let (Some(current_hash), Some(session_hash)) =
            (user.session_auth_hash(), session.auth_hash())
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
