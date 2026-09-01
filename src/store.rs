use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;

use crate::error::AuthResult;
use crate::session::{Session, SessionId};
use crate::user::AuthUser;

/// Storage interface for loading users by ID.
pub trait UserStore: Send + Sync + 'static {
    type User: AuthUser;

    /// Retrieve a user by their unique identifier.
    fn find_by_id(
        &self,
        id: &<Self::User as AuthUser>::Id,
    ) -> impl std::future::Future<Output = AuthResult<Option<Self::User>>> + Send;
}

/// Storage interface for managing session persistence and lifecycle.
pub trait SessionStore<UserId>: Send + Sync + 'static {
    /// Save a newly created session or update an existing one.
    fn save_session(
        &self,
        session: Session<UserId>,
    ) -> impl std::future::Future<Output = AuthResult<()>> + Send;

    /// Find an active session by its ID.
    fn find_session(
        &self,
        id: &SessionId,
    ) -> impl std::future::Future<Output = AuthResult<Option<Session<UserId>>>> + Send;

    /// Delete/revoke a session by ID.
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

/// An in-memory, thread-safe implementation of [`UserStore`] and [`SessionStore`].
///
/// Useful for testing, rapid prototyping, and lightweight mock environments.
#[derive(Debug, Default)]
pub struct MemoryStore<User: AuthUser> {
    users: RwLock<HashMap<User::Id, User>>,
    sessions: RwLock<HashMap<SessionId, Session<User::Id>>>,
}

impl<User: AuthUser> MemoryStore<User> {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or update a user in the store.
    pub fn insert_user(&self, user: User) {
        let mut users = self.users.write().expect("MemoryStore lock poisoned");
        users.insert(user.id(), user);
    }
}

impl<User: AuthUser> UserStore for MemoryStore<User> {
    type User = User;

    async fn find_by_id(&self, id: &User::Id) -> AuthResult<Option<User>> {
        let users = self.users.read().map_err(|e| crate::error::AuthError::Store(e.to_string()))?;
        Ok(users.get(id).cloned())
    }
}

impl<User: AuthUser> SessionStore<User::Id> for MemoryStore<User>
where
    User::Id: Eq + Hash + Clone + Send + Sync + 'static,
{
    async fn save_session(&self, session: Session<User::Id>) -> AuthResult<()> {
        let mut sessions = self.sessions.write().map_err(|e| crate::error::AuthError::Store(e.to_string()))?;
        sessions.insert(session.id().clone(), session);
        Ok(())
    }

    async fn find_session(&self, id: &SessionId) -> AuthResult<Option<Session<User::Id>>> {
        let sessions = self.sessions.read().map_err(|e| crate::error::AuthError::Store(e.to_string()))?;
        Ok(sessions.get(id).cloned())
    }

    async fn delete_session(&self, id: &SessionId) -> AuthResult<()> {
        let mut sessions = self.sessions.write().map_err(|e| crate::error::AuthError::Store(e.to_string()))?;
        sessions.remove(id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &User::Id) -> AuthResult<()> {
        let mut sessions = self.sessions.write().map_err(|e| crate::error::AuthError::Store(e.to_string()))?;
        sessions.retain(|_, session| session.user_id() != user_id);
        Ok(())
    }
}
