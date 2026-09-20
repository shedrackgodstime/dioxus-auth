//! Default in-memory store implementing all storage capability traits.

use std::fmt::Debug;

use parking_lot::RwLock;

use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{PasswordUserStore, UserStore};
use crate::user::AuthUser;

/// In-memory [`UserStore`], [`PasswordUserStore`], and [`SessionStore`].
///
/// Sessions are keyed by their storage-form id (`sha256(raw wire token)`).
/// The engine is responsible for passing the storage form.
///
/// Lookups are linear scans over `Vec`s — appropriate for the default
/// single-process development store. `Clone` neither blocks nor panics on a
/// poisoned lock: it falls back to an empty store (see `cloned_or_empty`).
#[derive(Debug)]
pub struct MemoryStore<User: AuthUser> {
    users: RwLock<Vec<User>>,
    credentials: RwLock<Vec<(String, User::Id, String)>>,
    sessions: RwLock<Vec<Session<User::Id>>>,
}

impl<User: AuthUser> Default for MemoryStore<User> {
    fn default() -> Self {
        return Self {
            users: RwLock::new(Vec::new()),
            credentials: RwLock::new(Vec::new()),
            sessions: RwLock::new(Vec::new()),
        };
    }
}

impl<User: AuthUser + Clone> Clone for MemoryStore<User> {
    fn clone(&self) -> Self {
        return Self {
            users: RwLock::new(cloned_or_empty(&self.users)),
            credentials: RwLock::new(cloned_or_empty(&self.credentials)),
            sessions: RwLock::new(cloned_or_empty(&self.sessions)),
        };
    }
}

fn cloned_or_empty<T: Clone>(lock: &RwLock<Vec<T>>) -> Vec<T> {
    return lock
        .try_read()
        .map_or_else(Vec::new, |guard| return guard.clone());
}

impl<User: AuthUser> MemoryStore<User> {
    /// Creates a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        return Self::default();
    }

    /// Inserts or updates a user without credentials.
    pub fn insert_user(&self, user: User) {
        let mut users = self.users.write();
        if let Some(existing) = users.iter_mut().find(|u| return u.id() == user.id()) {
            *existing = user;
        } else {
            users.push(user);
        }
    }

    /// Inserts or updates a user with login identifier and hashed password.
    pub fn insert_user_with_password(
        &self,
        user: User,
        identifier: impl Into<String>,
        password_hash: impl Into<String>,
    ) {
        let id = user.id();
        self.insert_user(user);
        let identifier = identifier.into();
        let hash = password_hash.into();
        {
            let mut credentials = self.credentials.write();
            if let Some(entry) = credentials
                .iter_mut()
                .find(|(ident, _, _)| return *ident == identifier)
            {
                entry.1 = id;
                entry.2 = hash;
            } else {
                credentials.push((identifier, id, hash));
            }
        }
    }
}

impl<User: AuthUser + Clone> UserStore for MemoryStore<User> {
    type Id = User::Id;
    type User = User;

    fn find_by_id(&self, id: &Self::Id) -> Result<Option<Self::User>, AuthError> {
        let user = {
            let users = self.users.read();
            users.iter().find(|u| return &u.id() == id).cloned()
        };
        return Ok(user);
    }
}

impl<User: AuthUser + Clone> PasswordUserStore for MemoryStore<User> {
    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<(Self::User, String)>, AuthError> {
        let credential = {
            let credentials = self.credentials.read();
            credentials
                .iter()
                .find(|(ident, _, _)| return ident == identifier)
                .map(|(_, user_id, hash)| return (user_id.clone(), hash.clone()))
        };
        let (user_id, password_hash) = match credential {
            Some(credential) => credential,
            None => return Ok(None),
        };
        let found = {
            let users = self.users.read();
            users.iter().find(|u| return u.id() == user_id).cloned()
        };
        let user = match found {
            Some(user) => user,
            None => return Ok(None),
        };
        return Ok(Some((user, password_hash)));
    }

    fn update_password(&self, id: &Self::Id, new_hash: &str) -> Result<(), AuthError> {
        {
            let mut credentials = self.credentials.write();
            for (_, user_id, hash) in credentials.iter_mut() {
                if user_id == id {
                    *hash = new_hash.to_string();
                    return Ok(());
                }
            }
        }
        return Ok(());
    }
}

impl<User: AuthUser + Clone> SessionStore for MemoryStore<User> {
    type Id = User::Id;

    fn save_session(&self, session: Session<Self::Id>) -> Result<(), AuthError> {
        {
            let mut sessions = self.sessions.write();
            if let Some(existing) = sessions.iter_mut().find(|s| return s.id() == session.id()) {
                *existing = session;
            } else {
                sessions.push(session);
            }
        }
        return Ok(());
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<Self::Id>>, AuthError> {
        let session = {
            let sessions = self.sessions.read();
            sessions.iter().find(|s| return s.id() == id).cloned()
        };
        return Ok(session);
    }

    fn delete_session(&self, id: &SessionId) -> Result<(), AuthError> {
        {
            let mut sessions = self.sessions.write();
            sessions.retain(|s| return s.id() != id);
        }
        return Ok(());
    }

    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> Result<(), AuthError> {
        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.iter_mut().find(|s| return s.id() == id) {
                let updated = session
                    .clone()
                    .set_expiry_and_last_active(new_expiry, last_active);
                *session = updated;
            }
        }
        return Ok(());
    }

    fn delete_user_sessions(&self, user_id: &Self::Id) -> Result<(), AuthError> {
        {
            let mut sessions = self.sessions.write();
            sessions.retain(|s| return s.user_id() != user_id);
        }
        return Ok(());
    }

    fn list_user_sessions(&self, user_id: &Self::Id) -> Result<Vec<Session<Self::Id>>, AuthError> {
        let sessions = {
            let sessions = self.sessions.read();
            sessions
                .iter()
                .filter(|s| return s.user_id() == user_id)
                .cloned()
                .collect()
        };
        return Ok(sessions);
    }
}
