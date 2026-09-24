//! Default store behind [`Auth::memory`](crate::auth::Auth::memory).
//!
//! Stores [`DefaultUser`](crate::user::DefaultUser) rows with generated `u64`
//! identities: signup takes [`DefaultUserInput`](crate::user::DefaultUserInput)
//! (a display name only) and the store mints the id from an atomic counter,
//! derives the email from the normalized signup identifier, and returns
//! exactly what it persisted. Beginners never invent a primary key.
//!
//! Sessions are keyed by their storage-form id (`sha256(raw wire token)`).
//! The engine is responsible for passing the storage form.
//!
//! Lookups are linear scans over `Vec`s and expired sessions drop lazily on
//! use, like [`MemoryStore`](crate::store::MemoryStore). Prototype-only:
//! everything dies with the process.
//!
//! `Debug` is **manual and redacted**: a derived impl would render credential
//! hashes, login identifiers, and full user rows. Counts preserve
//! debuggability without leaking store secrets.

use std::fmt::{self, Debug};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{PasswordUserStore, UserStore};
use crate::user::{DefaultUser, DefaultUserInput};

/// First generated user id.
const FIRST_USER_ID: u64 = 1;

/// Default [`UserStore`], [`PasswordUserStore`], and [`SessionStore`].
///
/// Created through [`Auth::memory`](crate::auth::Auth::memory); application
/// code names it only when spelling the facade type out.
pub struct DefaultStore {
    users: RwLock<Vec<DefaultUser>>,
    credentials: RwLock<Vec<(String, u64, String)>>,
    sessions: RwLock<Vec<Session<u64>>>,
    next_id: AtomicU64,
}

impl Debug for DefaultStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("DefaultStore")
            .field("users", &self.users.read().len())
            .field("credentials", &self.credentials.read().len())
            .field("sessions", &self.sessions.read().len())
            .field("next_id", &self.next_id.load(Ordering::Relaxed))
            .finish();
    }
}

impl Default for DefaultStore {
    fn default() -> Self {
        return Self {
            users: RwLock::new(Vec::new()),
            credentials: RwLock::new(Vec::new()),
            sessions: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(FIRST_USER_ID),
        };
    }
}

impl DefaultStore {
    /// Creates a new empty default store.
    #[must_use]
    pub fn new() -> Self {
        return Self::default();
    }
}

impl UserStore for DefaultStore {
    type Id = u64;
    type User = DefaultUser;

    fn find_by_id(&self, id: &Self::Id) -> Result<Option<Self::User>, AuthError> {
        let user = {
            let users = self.users.read();
            users.iter().find(|u| return &u.id == id).cloned()
        };
        return Ok(user);
    }
}

impl PasswordUserStore for DefaultStore {
    type NewUser = DefaultUserInput;

    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<(Self::User, String)>, AuthError> {
        let credential = {
            let credentials = self.credentials.read();
            credentials
                .iter()
                .find(|(ident, _, _)| return ident == identifier)
                .map(|(_, user_id, hash)| return (*user_id, hash.clone()))
        };
        let (user_id, password_hash) = match credential {
            Some(credential) => credential,
            None => return Ok(None),
        };
        let found = {
            let users = self.users.read();
            users.iter().find(|u| return u.id == user_id).cloned()
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
                }
            }
        }
        return Ok(());
    }

    // reason: the guard must stay held across the identifier check, the
    // existence check, and the push; releasing it earlier would split the
    // claim and let a racing provisioner steal the identifier in between.
    #[expect(clippy::significant_drop_tightening)]
    fn attach_password_credential(
        &self,
        id: &Self::Id,
        identifier: &str,
        password_hash: &str,
    ) -> Result<bool, AuthError> {
        // One guard order, both tables: `credentials` before `users`, matching
        // provisioning, so a racing provisioner and a racing attach cannot
        // deadlock or interleave a check past a write.
        let mut credentials = self.credentials.write();
        if credentials
            .iter()
            .any(|(ident, _, _)| return ident == identifier)
        {
            return Ok(false);
        }
        let known = {
            let users = self.users.read();
            users.iter().any(|existing| return existing.id == *id)
        };
        if !known {
            return Err(AuthError::InvalidCredentials);
        }
        credentials.push((identifier.to_string(), *id, password_hash.to_string()));
        return Ok(true);
    }

    // reason: the guard must stay held across the identifier check, the id
    // mint, and both pushes; releasing it earlier would split the claim.
    #[expect(clippy::significant_drop_tightening)]
    fn provision_user_with_password(
        &self,
        input: Self::NewUser,
        identifier: &str,
        password_hash: &str,
    ) -> Result<Option<Self::User>, AuthError> {
        // One guard order, both tables: `credentials` before `users`, held
        // across the identifier check, the id mint, and both pushes, so the
        // claim is one indivisible step. The counter alone already yields
        // fresh ids; the id check below honors the trait contract for the
        // unreachable wrap-around case.
        let mut credentials = self.credentials.write();
        if credentials
            .iter()
            .any(|(ident, _, _)| return ident == identifier)
        {
            return Ok(None);
        }
        let mut users = self.users.write();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if users.iter().any(|existing| return existing.id == id) {
            return Ok(None);
        }
        credentials.push((identifier.to_string(), id, password_hash.to_string()));
        let user = DefaultUser {
            id,
            email: identifier.to_string(),
            name: input.name,
        };
        users.push(user.clone());
        return Ok(Some(user));
    }
}

impl SessionStore for DefaultStore {
    type Id = u64;

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
