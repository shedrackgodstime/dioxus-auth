//! Default in-memory subject, credential, session, and application store.
//!
//! The prototype resolver: bundles subject infrastructure with an
//! application model for local development and tests. Signup takes the
//! finished user (caller-built, as before); the store mints the subject id
//! (or adopts an override), links the user's own id as the app key, and
//! returns exactly what it persisted.
//!
//! For zero-modeling quickstart (name-only input, generated app rows), see
//! [`DefaultStore`](crate::store::DefaultStore) behind
//! [`Auth::memory`](crate::auth::Auth::memory).
//!
//! Sessions are keyed by their storage-form id (`sha256(raw wire token)`).
//! The engine is responsible for passing the storage form.
//!
//! Lookups are linear scans over `Vec`s and expired sessions drop lazily on
//! use. Prototype-only: everything dies with the process.
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
use crate::store::user::{AuthSubject, CredentialStore, SubjectStore, UserStore};
use crate::user::AuthUser;

/// First minted subject id.
const FIRST_AUTH_ID: u64 = 1;

/// In-memory prototype store: subjects, credentials, sessions, and users.
///
/// One connection-equivalent behind locks: the identifier claim, the id
/// mint, and all writes land as one indivisible step under a single guard
/// order (`credentials`, `subjects`, then `users`), so racing signups
/// serialize instead of interleaving.
pub struct MemoryStore<User: AuthUser> {
    subjects: RwLock<Vec<AuthSubject<u64, User::Id>>>,
    credentials: RwLock<Vec<(String, String, u64, String)>>,
    users: RwLock<Vec<User>>,
    sessions: RwLock<Vec<Session<u64>>>,
    next_id: AtomicU64,
}

impl<User: AuthUser> Debug for MemoryStore<User> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("MemoryStore")
            .field("subjects", &self.subjects.read().len())
            .field("credentials", &self.credentials.read().len())
            .field("users", &self.users.read().len())
            .field("sessions", &self.sessions.read().len())
            .field("next_id", &self.next_id.load(Ordering::Relaxed))
            .finish();
    }
}

impl<User: AuthUser> Default for MemoryStore<User> {
    fn default() -> Self {
        return Self {
            subjects: RwLock::new(Vec::new()),
            credentials: RwLock::new(Vec::new()),
            users: RwLock::new(Vec::new()),
            sessions: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(FIRST_AUTH_ID),
        };
    }
}

impl<User: AuthUser + Clone> Clone for MemoryStore<User> {
    fn clone(&self) -> Self {
        return Self {
            subjects: RwLock::new(self.subjects.read().clone()),
            credentials: RwLock::new(self.credentials.read().clone()),
            users: RwLock::new(self.users.read().clone()),
            sessions: RwLock::new(self.sessions.read().clone()),
            next_id: AtomicU64::new(self.next_id.load(Ordering::Relaxed)),
        };
    }
}

/// Replaces the first entry matching the incoming value, or pushes it.
fn replace_or_push<T>(items: &mut Vec<T>, value: T, matches: impl Fn(&T, &T) -> bool) {
    if let Some(existing) = items
        .iter_mut()
        .find(|current| return matches(current, &value))
    {
        *existing = value;
    } else {
        items.push(value);
    }
}

impl<User: AuthUser> MemoryStore<User> {
    /// Creates a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        return Self::default();
    }
}

impl<User> MemoryStore<User>
where
    User: AuthUser<Id = u64>,
{
    /// Advances the subject mint past a seeded id.
    ///
    /// Seeded rows alias their subject id to the user id, so the counter
    /// must skip past them; otherwise a later mint would collide with a
    /// seeded row and fail a claim that should succeed.
    fn skip_minted_ids(&self, id: u64) {
        self.next_id
            .fetch_max(id.saturating_add(1), Ordering::Relaxed);
    }

    /// Inserts or updates a user without credentials.
    ///
    /// Test and seeding helper only: it bypasses the atomic signup claim,
    /// so registration flows must go through the store traits instead. Plants
    /// a matching subject row aliased to the user id with no version binding,
    /// so seeded rows validate like never-rotated subjects.
    pub fn insert_user(&self, user: User) {
        self.skip_minted_ids(user.id());
        let subject = AuthSubject {
            auth_id: user.id(),
            app_ref: Some(user.id()),
            auth_hash: None,
        };
        {
            let mut subjects = self.subjects.write();
            replace_or_push(&mut subjects, subject, |current, incoming| {
                return current.auth_id == incoming.auth_id;
            });
        }
        let mut users = self.users.write();
        replace_or_push(&mut users, user, |current, incoming| {
            return current.id() == incoming.id();
        });
    }

    /// Inserts or updates a user with login identifier and hashed password.
    ///
    /// Test and seeding helper only: it replaces the credential of an
    /// existing identifier without the taken-checks of provisioning. For
    /// registration, where a taken identifier must be rejected, use the
    /// store traits.
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
            replace_or_push(
                &mut credentials,
                (String::from("email"), identifier, id, hash),
                |current, incoming| {
                    return current.0 == incoming.0 && current.1 == incoming.1;
                },
            );
        }
    }
}

impl<User: AuthUser + Clone> SubjectStore for MemoryStore<User> {
    type AuthId = u64;
    type AppRef = User::Id;
    type AppSetup = User;

    // reason: the guard must stay held across the identifier check, the id
    // mint, and all three pushes; releasing it earlier would split the claim.
    #[expect(clippy::significant_drop_tightening)]
    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        let mut credentials = self.credentials.write();
        if credentials
            .iter()
            .any(|(prov, ident, _, _)| return prov == provider && ident == identifier)
        {
            return Ok(None);
        }
        let mut subjects = self.subjects.write();
        let auth_id =
            id_override.unwrap_or_else(|| return self.next_id.fetch_add(1, Ordering::Relaxed));
        if subjects.iter().any(|s| return s.auth_id == auth_id) {
            return Ok(None);
        }
        let mut users = self.users.write();
        let app_id = app.id();
        if users.iter().any(|existing| return existing.id() == app_id) {
            return Ok(None);
        }
        credentials.push((
            provider.to_string(),
            identifier.to_string(),
            auth_id,
            secret_hash.to_string(),
        ));
        users.push(app);
        let subject = AuthSubject {
            auth_id,
            app_ref: Some(app_id),
            auth_hash: Some(secret_hash.to_string()),
        };
        subjects.push(subject.clone());
        return Ok(Some(subject));
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        let subject = {
            let subjects = self.subjects.read();
            subjects
                .iter()
                .find(|s| return &s.auth_id == auth_id)
                .cloned()
        };
        return Ok(subject);
    }

    // reason: the guard must stay held across the existence check and the
    // link write; releasing it earlier would let a racing delete strand the
    // link on a missing subject.
    #[expect(clippy::significant_drop_tightening)]
    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError> {
        {
            let mut subjects = self.subjects.write();
            let Some(subject) = subjects.iter_mut().find(|s| return &s.auth_id == auth_id) else {
                return Err(AuthError::InvalidCredentials);
            };
            if subject
                .app_ref
                .as_ref()
                .is_some_and(|linked| return linked != app_ref)
            {
                return Ok(false);
            }
            subject.app_ref = Some(app_ref.clone());
        }
        return Ok(true);
    }

    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError> {
        let auth_id = {
            let subjects = self.subjects.read();
            subjects
                .iter()
                .find(|s| return s.app_ref.as_ref() == Some(app_ref))
                .map(|s| return s.auth_id)
        };
        return Ok(auth_id);
    }

    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        {
            let mut subjects = self.subjects.write();
            subjects.retain(|s| return &s.auth_id != auth_id);
        }
        {
            let mut credentials = self.credentials.write();
            credentials.retain(|(_, _, id, _)| return id != auth_id);
        }
        {
            let mut sessions = self.sessions.write();
            sessions.retain(|s| return s.auth_id() != auth_id);
        }
        return Ok(());
    }
}

impl<User: AuthUser + Clone> CredentialStore for MemoryStore<User> {
    fn find_credential(
        &self,
        provider: &str,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        let credential = {
            let credentials = self.credentials.read();
            credentials
                .iter()
                .find(|(prov, ident, _, _)| return prov == provider && ident == identifier)
                .map(|(_, _, auth_id, hash)| return (*auth_id, hash.clone()))
        };
        let (auth_id, secret_hash) = match credential {
            Some(credential) => credential,
            None => return Ok(None),
        };
        let found = {
            let subjects = self.subjects.read();
            subjects
                .iter()
                .find(|s| return s.auth_id == auth_id)
                .cloned()
        };
        let subject = match found {
            Some(subject) => subject,
            None => return Ok(None),
        };
        return Ok(Some((subject, secret_hash)));
    }

    // reason: the guard must stay held across the identifier check, the
    // existence check, and the push; releasing it earlier would split the
    // claim and let a racing provisioner steal the identifier in between.
    #[expect(clippy::significant_drop_tightening)]
    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        let mut credentials = self.credentials.write();
        if credentials
            .iter()
            .any(|(prov, ident, _, _)| return prov == provider && ident == identifier)
        {
            return Ok(false);
        }
        let known = {
            let subjects = self.subjects.read();
            subjects.iter().any(|s| return &s.auth_id == auth_id)
        };
        if !known {
            return Err(AuthError::InvalidCredentials);
        }
        credentials.push((
            provider.to_string(),
            identifier.to_string(),
            *auth_id,
            secret_hash.to_string(),
        ));
        return Ok(true);
    }

    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError> {
        {
            let mut credentials = self.credentials.write();
            for (_, _, id, hash) in credentials.iter_mut() {
                if id == auth_id {
                    *hash = new_hash.to_string();
                }
            }
        }
        {
            let mut subjects = self.subjects.write();
            for subject in subjects.iter_mut() {
                if &subject.auth_id == auth_id {
                    subject.auth_hash = Some(new_hash.to_string());
                }
            }
        }
        return Ok(());
    }
}

impl<User: AuthUser + Clone> SessionStore for MemoryStore<User> {
    type AuthId = u64;

    fn save_session(&self, session: Session<Self::AuthId>) -> Result<(), AuthError> {
        {
            let mut sessions = self.sessions.write();
            replace_or_push(&mut sessions, session, |current, incoming| {
                return current.id() == incoming.id();
            });
        }
        return Ok(());
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<Self::AuthId>>, AuthError> {
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

    fn delete_subject_sessions(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        {
            let mut sessions = self.sessions.write();
            sessions.retain(|s| return s.auth_id() != auth_id);
        }
        return Ok(());
    }

    fn list_subject_sessions(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Vec<Session<Self::AuthId>>, AuthError> {
        let sessions = {
            let sessions = self.sessions.read();
            sessions
                .iter()
                .filter(|s| return s.auth_id() == auth_id)
                .cloned()
                .collect()
        };
        return Ok(sessions);
    }
}

impl<User: AuthUser + Clone> UserStore for MemoryStore<User> {
    type User = User;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError> {
        let user = {
            let users = self.users.read();
            users.iter().find(|u| return &u.id() == app_ref).cloned()
        };
        return Ok(user);
    }
}
