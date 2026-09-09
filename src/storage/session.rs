use crate::error::AuthResult;
use crate::session::{Session, SessionId};

/// Storage interface for session persistence and lifecycle.
///
/// Implementations receive and return sessions whose `id` field is the
/// **storage form** — `sha256(raw wire token)`. [`AuthEngine`](crate::engine::AuthEngine)
/// hashes wire tokens before calling this trait.
///
/// ## Store contract (Spec 16)
///
/// 1. **find → delete (logout/revoke)**: deleting a session must permanently
///    remove it — no validation can resurrect it afterwards. The engine uses
///    [`touch_session_if_present`] to perform conditional updates that prevent
///    logout/rotate races from resurrecting a revoked session.
/// 2. **rotate-on-login**: [`delete_user_sessions`] must also eliminate the
///    window where a concurrent validate resurrects one. The conditional update
///    above closes this race.
/// 3. **Atomicity**: implementations are encouraged (but not required) to make
///    [`touch_session_if_present`] atomic with respect to [`delete_session`].
///    [`MemoryStore`] takes the write lock for the duration of the check-then-write.
pub trait SessionStore<UserId: Send>: Send + Sync + 'static {
    /// Save a newly created session or update an existing one.
    fn save_session(
        &self,
        session: Session<UserId>,
    ) -> impl std::future::Future<Output = AuthResult<()>> + Send;

    /// Find an active session by its storage-form id.
    fn find_session(
        &self,
        id: &SessionId,
    ) -> impl std::future::Future<Output = AuthResult<Option<Session<UserId>>>> + Send;

    /// Delete/revoke a session by its storage-form id.
    fn delete_session(
        &self,
        id: &SessionId,
    ) -> impl std::future::Future<Output = AuthResult<()>> + Send;

    /// Atomically extend a session's expiry + last_active only if it still exists.
    ///
    /// This is the key primitive for closing the logout/rotate resurrection race
    /// (Spec 16). The store must check that `id` is still present before applying
    /// the update. If the session was deleted (by logout or rotate) between the
    /// engine's read and this call, this method must be a no-op.
    ///
    /// Returns `Ok(())` whether the session was present or not — callers rely on
    /// the absence of resurrection, not on the return value.
    ///
    /// The provided default is a best-effort find-then-save for backward
    /// compatibility. It does **not** close the race — stores should override
    /// it with a conditional update (see [`MemoryStore`](crate::storage::MemoryStore)).
    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> impl std::future::Future<Output = AuthResult<()>> + Send {
        async move {
            if let Some(session) = self.find_session(id).await? {
                let updated = session.set_expiry_and_last_active(new_expiry, last_active);
                self.save_session(updated).await?;
            }
            Ok(())
        }
    }

    /// Delete all active sessions belonging to a user.
    fn delete_user_sessions(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = AuthResult<()>> + Send;

    /// List all active sessions belonging to a user.
    fn list_user_sessions(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = AuthResult<Vec<Session<UserId>>>> + Send;
}
