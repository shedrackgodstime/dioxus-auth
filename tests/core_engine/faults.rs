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
    Auth, AuthEngine, AuthError, MemoryStore, PasswordUserStore, Session, SessionId, SessionStore,
    UserStore,
};

/// A full store decorator failing only `save_session`.
#[derive(Debug)]
struct FailingSaveStore {
    inner: MemoryStore<TestUser>,
}

impl UserStore for FailingSaveStore {
    type Id = u64;
    type User = TestUser;

    fn find_by_id(&self, id: &Self::Id) -> Result<Option<Self::User>, AuthError> {
        return self.inner.find_by_id(id);
    }
}

impl PasswordUserStore for FailingSaveStore {
    type NewUser = TestUser;

    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<(Self::User, String)>, AuthError> {
        return self.inner.find_by_identifier(identifier);
    }

    fn update_password(&self, id: &Self::Id, new_hash: &str) -> Result<(), AuthError> {
        return self.inner.update_password(id, new_hash);
    }

    fn provision_user_with_password(
        &self,
        input: Self::NewUser,
        identifier: &str,
        password_hash: &str,
    ) -> Result<Option<Self::User>, AuthError> {
        return self
            .inner
            .provision_user_with_password(input, identifier, password_hash);
    }
}

impl SessionStore for FailingSaveStore {
    type Id = u64;

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

    fn delete_user_sessions(&self, user_id: &u64) -> Result<(), AuthError> {
        return self.inner.delete_user_sessions(user_id);
    }

    fn list_user_sessions(&self, user_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return self.inner.list_user_sessions(user_id);
    }
}

/// A full store decorator failing only `delete_user_sessions`.
#[derive(Debug)]
struct FailingRevokeStore {
    inner: MemoryStore<TestUser>,
}

impl UserStore for FailingRevokeStore {
    type Id = u64;
    type User = TestUser;

    fn find_by_id(&self, id: &Self::Id) -> Result<Option<Self::User>, AuthError> {
        return self.inner.find_by_id(id);
    }
}

impl PasswordUserStore for FailingRevokeStore {
    type NewUser = TestUser;

    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<(Self::User, String)>, AuthError> {
        return self.inner.find_by_identifier(identifier);
    }

    fn update_password(&self, id: &Self::Id, new_hash: &str) -> Result<(), AuthError> {
        return self.inner.update_password(id, new_hash);
    }

    fn provision_user_with_password(
        &self,
        input: Self::NewUser,
        identifier: &str,
        password_hash: &str,
    ) -> Result<Option<Self::User>, AuthError> {
        return self
            .inner
            .provision_user_with_password(input, identifier, password_hash);
    }
}

impl SessionStore for FailingRevokeStore {
    type Id = u64;

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

    fn delete_user_sessions(&self, _user_id: &u64) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn list_user_sessions(&self, user_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return self.inner.list_user_sessions(user_id);
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
            .list_user_sessions(&1)
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
