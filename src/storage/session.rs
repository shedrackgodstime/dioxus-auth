use crate::error::AuthResult;
use crate::session::{Session, SessionId};

/// Storage interface for session persistence and lifecycle.
///
/// Implementations receive and return sessions whose `id` field is the
/// **storage form** — `sha256(raw wire token)`. [`AuthEngine`](crate::engine::AuthEngine)
/// hashes wire tokens before calling this trait.
pub trait SessionStore<UserId>: Send + Sync + 'static {
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
