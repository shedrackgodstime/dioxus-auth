use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;

use crate::error::AuthResult;
use crate::session::{Session, SessionId};
use crate::storage::session::SessionStore;
use crate::storage::user::{PasswordUserStore, UserStore};
use crate::user::AuthUser;

/// In-memory [`UserStore`], [`PasswordUserStore`], and [`SessionStore`].
///
/// Sessions are keyed by whatever ID is passed in. The engine is responsible
/// for passing the storage form (`sha256(raw wire token)`).
#[derive(Debug, Default)]
pub struct MemoryStore<User: AuthUser> {
    users: RwLock<HashMap<User::Id, User>>,
    credentials: RwLock<HashMap<String, (User::Id, String)>>,
    sessions: RwLock<HashMap<SessionId, Session<User::Id>>>,
}

impl<User: AuthUser> Clone for MemoryStore<User> {
    fn clone(&self) -> Self {
        Self {
            users: RwLock::new(self.users.read().expect("lock poisoned").clone()),
            credentials: RwLock::new(self.credentials.read().expect("lock poisoned").clone()),
            sessions: RwLock::new(self.sessions.read().expect("lock poisoned").clone()),
        }
    }
}

impl<User: AuthUser> MemoryStore<User> {
    fn read_lock<T>(lock: &RwLock<T>) -> AuthResult<std::sync::RwLockReadGuard<'_, T>> {
        lock.read()
            .map_err(|e| crate::error::AuthError::Store(e.to_string()))
    }

    fn write_lock<T>(lock: &RwLock<T>) -> AuthResult<std::sync::RwLockWriteGuard<'_, T>> {
        lock.write()
            .map_err(|e| crate::error::AuthError::Store(e.to_string()))
    }

    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            credentials: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or update a user without credentials.
    pub fn insert_user(&self, user: User) {
        let mut users = self.users.write().expect("lock poisoned");
        users.insert(user.id(), user);
    }

    /// Insert or update a user with login identifier and hashed password.
    pub fn insert_user_with_password(
        &self,
        user: User,
        identifier: impl Into<String>,
        password_hash: impl Into<String>,
    ) {
        let id = user.id();
        let mut users = self.users.write().expect("MemoryStore lock poisoned");
        users.insert(id.clone(), user);

        let mut credentials = self.credentials.write().expect("MemoryStore lock poisoned");
        credentials.insert(identifier.into(), (id, password_hash.into()));
    }
}

impl<User: AuthUser> UserStore for MemoryStore<User> {
    type User = User;

    async fn find_by_id(&self, id: &User::Id) -> AuthResult<Option<User>> {
        let users = Self::read_lock(&self.users)?;
        Ok(users.get(id).cloned())
    }
}

impl<User: AuthUser> PasswordUserStore for MemoryStore<User> {
    async fn find_by_identifier(&self, identifier: &str) -> AuthResult<Option<(User, String)>> {
        let credentials = Self::read_lock(&self.credentials)?;
        if let Some((user_id, hash)) = credentials.get(identifier) {
            let users = Self::read_lock(&self.users)?;
            if let Some(user) = users.get(user_id) {
                return Ok(Some((user.clone(), hash.clone())));
            }
        }
        Ok(None)
    }
}

impl<User: AuthUser> SessionStore<User::Id> for MemoryStore<User>
where
    User::Id: Eq + Hash + Clone + Send + Sync + 'static,
{
    async fn save_session(&self, session: Session<User::Id>) -> AuthResult<()> {
        let mut sessions = Self::write_lock(&self.sessions)?;
        sessions.insert(session.id().clone(), session);
        Ok(())
    }

    async fn find_session(&self, id: &SessionId) -> AuthResult<Option<Session<User::Id>>> {
        let sessions = Self::read_lock(&self.sessions)?;
        Ok(sessions.get(id).cloned())
    }

    async fn delete_session(&self, id: &SessionId) -> AuthResult<()> {
        let mut sessions = Self::write_lock(&self.sessions)?;
        sessions.remove(id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &User::Id) -> AuthResult<()> {
        let mut sessions = Self::write_lock(&self.sessions)?;
        sessions.retain(|_, session| session.user_id() != user_id);
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &User::Id) -> AuthResult<Vec<Session<User::Id>>> {
        let sessions = Self::read_lock(&self.sessions)?;
        Ok(sessions
            .values()
            .filter(|session| session.user_id() == user_id)
            .cloned()
            .collect())
    }
}
