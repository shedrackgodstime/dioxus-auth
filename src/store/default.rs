//! Default store behind [`Auth::memory`](crate::auth::Auth::memory).
//!
//! Bundles subject infrastructure with a built-in application model:
//! signup takes [`DefaultUserInput`](crate::user::DefaultUserInput) (a
//! display name only), the store mints both the subject id and the app row
//! id from atomic counters, derives the email from the normalized signup
//! identifier, and returns exactly what it persisted. Beginners never
//! invent a primary key.
//!
//! Sessions are keyed by their storage-form id (`sha256(raw wire token)`).
//! The engine is responsible for passing the storage form.
//!
//! Lookups are linear scans over `Vec`s and expired sessions drop lazily on
//! use. Prototype-only: everything dies with the process.
//!
//! `Debug` is **manual and redacted**: a derived impl would render credential
//! hashes, login identifiers, and subject rows. Counts preserve
//! debuggability without leaking store secrets.

use std::fmt::{self, Debug};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{AuthSubject, CredentialStore, SubjectStore, UserStore};
use crate::user::{DefaultUser, DefaultUserInput};

/// First minted subject id.
const FIRST_AUTH_ID: u64 = 1;

/// First minted application row id.
const FIRST_APP_ID: u64 = 1;

/// Default subject, credential, session, and application store.
///
/// Created through [`Auth::memory`](crate::auth::Auth::memory); application
/// code names it only when spelling the facade type out.
pub struct DefaultStore {
    subjects: RwLock<Vec<AuthSubject<u64, u64>>>,
    credentials: RwLock<Vec<(String, u64, String)>>,
    users: RwLock<Vec<DefaultUser>>,
    sessions: RwLock<Vec<Session<u64>>>,
    next_auth_id: AtomicU64,
    next_app_id: AtomicU64,
}

impl Debug for DefaultStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("DefaultStore")
            .field("subjects", &self.subjects.read().len())
            .field("credentials", &self.credentials.read().len())
            .field("users", &self.users.read().len())
            .field("sessions", &self.sessions.read().len())
            .field("next_auth_id", &self.next_auth_id.load(Ordering::Relaxed))
            .field("next_app_id", &self.next_app_id.load(Ordering::Relaxed))
            .finish();
    }
}

impl Default for DefaultStore {
    fn default() -> Self {
        return Self {
            subjects: RwLock::new(Vec::new()),
            credentials: RwLock::new(Vec::new()),
            users: RwLock::new(Vec::new()),
            sessions: RwLock::new(Vec::new()),
            next_auth_id: AtomicU64::new(FIRST_AUTH_ID),
            next_app_id: AtomicU64::new(FIRST_APP_ID),
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

impl SubjectStore for DefaultStore {
    type AuthId = u64;
    type AppRef = u64;
    type AppSetup = DefaultUserInput;

    // reason: the guard must stay held across the identifier check, both
    // mints, and all three pushes; releasing it earlier would split the
    // claim.
    #[expect(clippy::significant_drop_tightening)]
    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        // One guard order, all tables: `credentials`, `subjects`, then
        // `users`, held across the identifier check, both mints, and all
        // pushes, so the claim is one indivisible step.
        let mut credentials = self.credentials.write();
        if credentials
            .iter()
            .any(|(ident, _, _)| return ident == identifier)
        {
            return Ok(None);
        }
        let mut subjects = self.subjects.write();
        let auth_id =
            id_override.unwrap_or_else(|| return self.next_auth_id.fetch_add(1, Ordering::Relaxed));
        if subjects.iter().any(|s| return s.auth_id == auth_id) {
            return Ok(None);
        }
        let mut users = self.users.write();
        let app_id = self.next_app_id.fetch_add(1, Ordering::Relaxed);
        if users.iter().any(|u| return u.id == app_id) {
            return Ok(None);
        }
        credentials.push((identifier.to_string(), auth_id, secret_hash.to_string()));
        users.push(DefaultUser {
            id: app_id,
            email: identifier.to_string(),
            name: app.name,
        });
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
            subject.app_ref = Some(*app_ref);
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
            credentials.retain(|(_, id, _)| return id != auth_id);
        }
        {
            let mut sessions = self.sessions.write();
            sessions.retain(|s| return s.auth_id() != auth_id);
        }
        return Ok(());
    }
}

impl CredentialStore for DefaultStore {
    fn find_credential(
        &self,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        let credential = {
            let credentials = self.credentials.read();
            credentials
                .iter()
                .find(|(ident, _, _)| return ident == identifier)
                .map(|(_, auth_id, hash)| return (*auth_id, hash.clone()))
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
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        let mut credentials = self.credentials.write();
        if credentials
            .iter()
            .any(|(ident, _, _)| return ident == identifier)
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
        credentials.push((identifier.to_string(), *auth_id, secret_hash.to_string()));
        return Ok(true);
    }

    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError> {
        {
            let mut credentials = self.credentials.write();
            for (_, id, hash) in credentials.iter_mut() {
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

impl SessionStore for DefaultStore {
    type AuthId = u64;

    fn save_session(&self, session: Session<Self::AuthId>) -> Result<(), AuthError> {
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

impl UserStore for DefaultStore {
    type User = DefaultUser;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError> {
        let user = {
            let users = self.users.read();
            users.iter().find(|u| return &u.id == app_ref).cloned()
        };
        return Ok(user);
    }
}
