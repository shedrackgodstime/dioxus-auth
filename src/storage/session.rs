use crate::error::AuthResult;
use crate::session::{Session, SessionId};

/// Storage interface for managing session persistence and lifecycle.
///
/// # Hashing contract
///
/// Implementations receive and return session records whose `id` field is the
/// **storage form** — `sha256(raw wire token)`. [`crate::engine::AuthEngine`]
/// is the boundary that hashes wire tokens before calling this trait and
/// re-hashes incoming raw tokens before lookup. A leaked store therefore
/// yields no session-hijackable secrets.
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

    /// Delete all active sessions belonging to a user (e.g. upon password change or total logout).
    fn delete_user_sessions(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = AuthResult<()>> + Send;
}
