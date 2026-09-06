//! Test helpers and conformance tests for [`UserStore`], [`PasswordUserStore`], and [`SessionStore`] implementations.
//!
//! Replicate these tests against your store. For user and engine tests, pre-seed
//! your store with a test user, then run the checks:
//!
//! ```rust,ignore
//! #[cfg(test)]
//! mod tests {
//!     use std::sync::Arc;
//!     use dioxus_auth::{tests::*, AuthEngine, Argon2Hasher};
//!
//!     #[tokio::test]
//!     async fn my_sqlite_store_follows_contract() {
//!         let store = Arc::new(MySqliteStore::new_in_memory());
//!         let hasher = Argon2Hasher::new();
//!         let (user, hash) = seeded_test_user(1, "alice@example.com", "password123");
//!         store.create_user_for_testing(user, &hash).await.unwrap();
//!
//!         run_user_store_tests(store.clone()).await;
//!         run_password_user_store_tests(store.clone(), &hasher).await;
//!         run_session_store_tests(store.clone()).await;
//!         run_engine_lifecycle_tests(store.clone(), store.clone()).await;
//!     }
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use crate::security::Argon2Hasher;
use crate::security::PasswordHasher;
use crate::session::{Session, SessionId};
use crate::storage::session::SessionStore;
use crate::storage::user::{PasswordUserStore, UserStore};
use crate::user::AuthUser;

// Test user fixture

/// Minimal `AuthUser` for store conformance tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestUser {
    pub id: u64,
    pub email: String,
    pub password_hash: String,
}

impl AuthUser for TestUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}

impl TestUser {
    /// Create a new [`TestUser`] with the given id and email.
    pub fn new(id: u64, email: &str) -> Self {
        Self {
            id,
            email: email.to_string(),
            password_hash: String::new(),
        }
    }

    /// Set the password hash on this user.
    pub fn with_password_hash(mut self, hash: &str) -> Self {
        self.password_hash = hash.to_string();
        self
    }
}

// UserStore tests

/// Run [`UserStore`] conformance tests.
///
/// Pre-seed the store with a user `id == 1` and `email == "alice@example.com"`.
pub async fn run_user_store_tests<S>(store: Arc<S>)
where
    S: UserStore<User = TestUser>,
{
    // find_by_id returns Some for an existing user
    let found = store
        .find_by_id(&1)
        .await
        .expect("find_by_id must not error");
    assert_eq!(
        found,
        Some(TestUser::new(1, "alice@example.com")),
        "find_by_id must return the inserted user"
    );

    // find_by_id returns None for unknown id
    let missing = store
        .find_by_id(&999)
        .await
        .expect("find_by_id must not error");
    assert!(
        missing.is_none(),
        "find_by_id must return None for unknown id"
    );
}

// PasswordUserStore tests

/// Run [`PasswordUserStore`] conformance tests.
///
/// Pre-seed the store with a user `id == 1`, `email == "alice@example.com"`,
/// and a known password hash for `"password123"`.
pub async fn run_password_user_store_tests<S>(store: Arc<S>, hasher: &Argon2Hasher)
where
    S: PasswordUserStore<User = TestUser>,
{
    // find_by_identifier returns Some for the seeded user's email
    let found = store
        .find_by_identifier("alice@example.com")
        .await
        .expect("find_by_identifier must not error");
    assert!(
        found.is_some(),
        "find_by_identifier must return Some for known identifier"
    );
    let (user, stored_hash) = found.unwrap();
    assert_eq!(user.id(), 1);
    assert_eq!(user.email, "alice@example.com");

    // The stored hash must verify against the original password
    let is_valid = hasher
        .verify_password("password123", &stored_hash)
        .expect("verification must not error");
    assert!(
        is_valid,
        "stored hash must verify against original password"
    );

    // find_by_identifier returns None for unknown identifier
    let missing = store
        .find_by_identifier("nobody@example.com")
        .await
        .expect("find_by_identifier must not error");
    assert!(
        missing.is_none(),
        "find_by_identifier must return None for unknown identifier"
    );
}

// SessionStore tests

/// Run [`SessionStore`] conformance tests. Fully self-contained.
pub async fn run_session_store_tests<S>(store: Arc<S>)
where
    S: SessionStore<u64>,
{
    let session_id = SessionId::new("test_session_abc123");
    let user_id = 42u64;
    let now = Duration::from_secs(1_000_000).as_secs();
    let expires = now + 3600;

    let session = Session::new(session_id.clone(), user_id, now, expires);

    // Save and retrieve
    store
        .save_session(session.clone())
        .await
        .expect("save_session must not error");
    let found = store
        .find_session(&session_id)
        .await
        .expect("find_session must not error");
    assert_eq!(found, Some(session.clone()));

    // Unknown session returns None
    let unknown = SessionId::new("does_not_exist");
    let missing = store
        .find_session(&unknown)
        .await
        .expect("find_session must not error");
    assert!(missing.is_none());

    // Delete session
    store
        .delete_session(&session_id)
        .await
        .expect("delete_session must not error");
    let after_delete = store
        .find_session(&session_id)
        .await
        .expect("find_session must not error");
    assert!(after_delete.is_none());

    // Delete user sessions
    let session2 = Session::new(SessionId::new("session_2"), user_id, now, expires);
    let session3 = Session::new(SessionId::new("session_3"), 99, now, expires);
    store.save_session(session2.clone()).await.expect("save");
    store.save_session(session3.clone()).await.expect("save");

    store
        .delete_user_sessions(&user_id)
        .await
        .expect("delete_user_sessions must not error");

    let remaining_for_user = store
        .find_session(session2.id())
        .await
        .expect("find_session must not error");
    assert!(
        remaining_for_user.is_none(),
        "user's sessions must be deleted"
    );

    let remaining_for_other = store
        .find_session(session3.id())
        .await
        .expect("find_session must not error");
    assert!(
        remaining_for_other.is_some(),
        "other user's sessions must not be deleted"
    );

    // List user sessions
    let session4 = Session::new(SessionId::new("session_4"), user_id, now, expires);
    let session5 = Session::new(SessionId::new("session_5"), 99, now, expires);
    store.save_session(session4.clone()).await.expect("save");
    store.save_session(session5.clone()).await.expect("save");

    let listed = store
        .list_user_sessions(&user_id)
        .await
        .expect("list_user_sessions must not error");
    assert_eq!(listed.len(), 2, "must list only the target user's sessions");
    assert!(listed.iter().any(|s| s.id() == session4.id()));
    assert!(listed.iter().any(|s| s.id() == session5.id()));
}

// Engine lifecycle tests

/// Run [`AuthEngine`] lifecycle conformance tests.
///
/// Pre-seed the store with a user `id == 1`, `email == "alice@example.com"`,
/// password hash for `"password123"`.
pub async fn run_engine_lifecycle_tests<U, S>(users: Arc<U>, sessions: Arc<S>)
where
    U: PasswordUserStore<User = TestUser>,
    S: SessionStore<u64>,
{
    let engine = crate::AuthEngine::builder(users.clone(), sessions.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    // Login success
    let (authed, session) = engine
        .login("alice@example.com", "password123")
        .await
        .expect("login must succeed with correct credentials");
    assert_eq!(authed.id(), 1);
    assert_eq!(authed.email, "alice@example.com");

    // Validate session
    let validated = engine
        .validate_session(session.id())
        .await
        .expect("validate_session must not error");
    assert_eq!(validated, Some(authed.clone()));

    // Login failure — wrong password
    let bad_login = engine.login("alice@example.com", "wrong").await;
    assert_eq!(bad_login.unwrap_err(), crate::AuthError::Unauthenticated);

    // Logout
    engine
        .logout(session.id())
        .await
        .expect("logout must not error");
    let after_logout = engine
        .validate_session(session.id())
        .await
        .expect("validate_session must not error");
    assert!(after_logout.is_none());
}

// Store fixture helpers

/// Create a seeded [`TestUser`] with a known password hash.
pub fn seeded_test_user(id: u64, email: &str) -> (TestUser, String) {
    let hasher = Argon2Hasher::new();
    let hash = hasher
        .hash_password("password123")
        .expect("hasher must not fail");
    let user = TestUser::new(id, email).with_password_hash(&hash);
    (user, hash)
}
