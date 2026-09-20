//! Session storage capability trait.

use std::fmt::Debug;

use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;

/// Storage interface for session persistence and lifecycle.
///
/// Sessions are keyed by the **storage form** — `sha256(raw wire token)`.
/// The engine hashes wire tokens before calling this trait, so the store
/// only ever sees hashed ids and a leaked store yields no session-hijackable
/// secrets.
pub trait SessionStore: Debug + Send + Sync {
    /// The user identifier type.
    type Id: Clone + Eq + Debug + Send + Sync + 'static;

    /// Saves a newly created or updated session.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed save must be handled"]
    fn save_session(&self, session: Session<Self::Id>) -> Result<(), AuthError>;

    /// Finds a session by its storage-form id.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the session must be used"]
    fn find_session(&self, id: &SessionId) -> Result<Option<Session<Self::Id>>, AuthError>;

    /// Deletes a session by its storage-form id.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed deletion must be handled"]
    fn delete_session(&self, id: &SessionId) -> Result<(), AuthError>;

    /// Atomically extends a session's expiry + `last_active` only if it still exists.
    ///
    /// Closes the logout/rotate resurrection race. If the session was deleted
    /// between the engine's read and this call, this must be a no-op.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed touch must be handled"]
    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> Result<(), AuthError>;

    /// Deletes all sessions belonging to a user.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed revoke must be handled"]
    fn delete_user_sessions(&self, user_id: &Self::Id) -> Result<(), AuthError>;

    /// Lists all sessions belonging to a user.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the session list must be used"]
    fn list_user_sessions(&self, user_id: &Self::Id) -> Result<Vec<Session<Self::Id>>, AuthError>;
}
