//! Store-fault injection: failures mid-verb must leave prior state intact.
//!
//! Login saves before it rotates and `change_password` revokes before it
//! writes, so a store failure reports the error with nothing irreplaceable
//! lost: a failed save keeps old sessions, a failed revoke keeps the old
//! credential. These tests pin both orderings with decorators that fail a
//! single store operation.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use super::common::TestUser;
use super::password::hash_password;
use dioxus_auth::{
    Auth, AuthEngine, AuthError, AuthSubject, CredentialStore, MemoryStore, Session, SessionId,
    SessionStore, SubjectStore, UserStore,
};

/// A full store decorator failing only `save_session`.
#[derive(Debug)]
struct FailingSaveStore {
    inner: MemoryStore<TestUser>,
}

impl SubjectStore for FailingSaveStore {
    type AuthId = u64;
    type AppRef = u64;
    type AppSetup = TestUser;

    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        return self
            .inner
            .provision_subject(id_override, app, identifier, secret_hash);
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        return self.inner.find_subject(auth_id);
    }

    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError> {
        return self.inner.set_app_link(auth_id, app_ref);
    }

    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError> {
        return self.inner.find_auth_id(app_ref);
    }

    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        return self.inner.delete_subject(auth_id);
    }
}

impl CredentialStore for FailingSaveStore {
    fn find_credential(
        &self,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        return self.inner.find_credential(identifier);
    }

    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        return self
            .inner
            .attach_credential(auth_id, identifier, secret_hash);
    }

    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError> {
        return self.inner.rotate_secret(auth_id, new_hash);
    }
}

impl UserStore for FailingSaveStore {
    type User = TestUser;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError> {
        return self.inner.resolve(app_ref);
    }
}

impl SessionStore for FailingSaveStore {
    type AuthId = u64;

    fn save_session(&self, _session: Session<u64>) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<u64>>, AuthError> {
        return self.inner.find_session(id);
    }

    fn delete_session(&self, id: &SessionId) -> Result<(), AuthError> {
        return self.inner.delete_session(id);
    }

    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> Result<(), AuthError> {
        return self
            .inner
            .touch_session_if_present(id, new_expiry, last_active);
    }

    fn delete_subject_sessions(&self, auth_id: &u64) -> Result<(), AuthError> {
        return self.inner.delete_subject_sessions(auth_id);
    }

    fn list_subject_sessions(&self, auth_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return self.inner.list_subject_sessions(auth_id);
    }
}

/// A full store decorator failing only `delete_subject_sessions`.
#[derive(Debug)]
struct FailingRevokeStore {
    inner: MemoryStore<TestUser>,
}

impl SubjectStore for FailingRevokeStore {
    type AuthId = u64;
    type AppRef = u64;
    type AppSetup = TestUser;

    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        return self
            .inner
            .provision_subject(id_override, app, identifier, secret_hash);
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        return self.inner.find_subject(auth_id);
    }

    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError> {
        return self.inner.set_app_link(auth_id, app_ref);
    }

    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError> {
        return self.inner.find_auth_id(app_ref);
    }

    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        return self.inner.delete_subject(auth_id);
    }
}

impl CredentialStore for FailingRevokeStore {
    fn find_credential(
        &self,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        return self.inner.find_credential(identifier);
    }

    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        return self
            .inner
            .attach_credential(auth_id, identifier, secret_hash);
    }

    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError> {
        return self.inner.rotate_secret(auth_id, new_hash);
    }
}

impl UserStore for FailingRevokeStore {
    type User = TestUser;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError> {
        return self.inner.resolve(app_ref);
    }
}

impl SessionStore for FailingRevokeStore {
    type AuthId = u64;

    fn save_session(&self, session: Session<u64>) -> Result<(), AuthError> {
        return self.inner.save_session(session);
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<u64>>, AuthError> {
        return self.inner.find_session(id);
    }

    fn delete_session(&self, id: &SessionId) -> Result<(), AuthError> {
        return self.inner.delete_session(id);
    }

    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> Result<(), AuthError> {
        return self
            .inner
            .touch_session_if_present(id, new_expiry, last_active);
    }

    fn delete_subject_sessions(&self, _auth_id: &u64) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn list_subject_sessions(&self, auth_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return self.inner.list_subject_sessions(auth_id);
    }
}

#[test]
fn login_save_failure_keeps_old_sessions_and_reports_the_error() {
    let users = Arc::new(MemoryStore::<TestUser>::new());
    users.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let sessions = MemoryStore::<TestUser>::new();
    let seeded_wire = SessionId::generate();
    let seeded_storage = seeded_wire.hash_for_storage();
    sessions
        .save_session(Session::new(seeded_storage, 1, 1_000, 9_999_999_999).with_last_active(1_000))
        .expect("seeding must succeed");
    let store = Arc::new(FailingSaveStore { inner: sessions });
    let engine = AuthEngine::builder(Arc::clone(&users), Arc::clone(&store))
        .build()
        .expect("engine construction must succeed");

    let failed = engine.login("alice", "pw");
    assert!(failed.is_err());

    assert_eq!(
        store
            .list_subject_sessions(&1)
            .expect("listing must succeed")
            .len(),
        1,
        "a failed save must not rotate prior sessions away"
    );
    assert!(
        engine
            .validate_session(&seeded_wire)
            .expect("validation must succeed")
            .is_some(),
        "the seeded session must still validate"
    );
}

#[test]
fn change_password_revoke_failure_keeps_the_old_credential() {
    let seeded = MemoryStore::<TestUser>::new();
    seeded.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(FailingRevokeStore { inner: seeded });
    let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .build()
        .expect("engine construction must succeed");
    let auth = Auth::from_engine(engine);

    let failed = auth.change_password("alice", "pw", "new-secret");
    assert!(failed.is_err());

    assert!(
        auth.sign_in_email("alice", "pw").is_ok(),
        "a failed revoke must leave the old credential untouched"
    );
    assert!(
        auth.sign_in_email("alice", "new-secret").is_err(),
        "the new hash must not have been written"
    );
}
