//! Engine behavior unit tests: options, hooks configuration, rotation, cloning.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use super::common::TestUser;
use super::identity_hasher::IdentityHasher;
use super::password::hash_password;
use dioxus_auth::{
    AuthEngine, AuthError, AuthStatus, CredentialStore, LoginOptions, MemoryStore, Session,
    SessionId, SessionStore, SubjectStore, UserStore,
};

fn seeded_login_engine() -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    return AuthEngine::builder(Arc::clone(&store), store)
        .build()
        .expect("engine construction must succeed");
}

#[test]
fn default_clock_records_current_time_on_login() {
    let engine = seeded_login_engine();
    let (_, session) = engine.login("alice", "pw").expect("login must succeed");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| return duration.as_secs());
    assert!(session.created_at_unix().abs_diff(now) <= 5);
}

#[test]
fn auth_status_variants_compare_by_value() {
    assert_eq!(
        AuthStatus::<u64>::Authenticated(7),
        AuthStatus::<u64>::Authenticated(7)
    );
    assert_ne!(
        AuthStatus::<u64>::Authenticated(7),
        AuthStatus::<u64>::Authenticated(8)
    );
    assert_eq!(AuthStatus::<u64>::Guest, AuthStatus::<u64>::Guest);
    assert_eq!(AuthStatus::<u64>::Loading, AuthStatus::<u64>::Loading);
}

#[test]
fn malformed_wire_tokens_are_cheap_rejections() {
    let engine = seeded_login_engine();
    let malformed = SessionId::new("not-a-64-char-hex-token");

    assert!(engine.validate_session(&malformed).unwrap().is_none());
    assert!(engine.logout(&malformed).is_ok());
    assert!(!engine.revoke_session(&malformed).unwrap());
}

#[test]
fn login_options_accessors_and_helpers() {
    let empty = LoginOptions::new();
    assert_eq!(empty.ip_address(), None);
    assert_eq!(empty.user_agent(), None);
    assert_eq!(LoginOptions::default(), empty);

    let filled = empty
        .with_ip_address(Some("198.51.100.1"))
        .with_user_agent(Some("agent"));
    assert_eq!(filled.ip_address(), Some("198.51.100.1"));
    assert_eq!(filled.user_agent(), Some("agent"));
}

#[test]
fn login_without_options_has_no_client_metadata() {
    let engine = seeded_login_engine();

    let (_, session) = engine.login("alice", "pw").unwrap();
    assert_eq!(session.ip_address(), None);
    assert_eq!(session.user_agent(), None);
}

#[test]
fn login_with_options_records_ip_and_user_agent() {
    let engine = seeded_login_engine();
    let options = LoginOptions::new()
        .with_ip_address(Some("203.0.113.7"))
        .with_user_agent(Some("dioxus-test/1.0"));

    let (subject, session) = engine.login_with_options("alice", "pw", options).unwrap();
    assert_eq!(subject.auth_id, 1);
    assert_eq!(session.ip_address(), Some("203.0.113.7"));
    assert_eq!(session.user_agent(), Some("dioxus-test/1.0"));

    let storage_id = session.id().hash_for_storage();
    let stored = engine
        .session_store()
        .find_session(&storage_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.ip_address(), Some("203.0.113.7"));
    assert_eq!(stored.user_agent(), Some("dioxus-test/1.0"));
}

#[test]
fn custom_hasher_override_is_used_for_verification() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", String::from("correct"));
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .hasher(IdentityHasher)
        .build()
        .expect("engine construction must succeed");

    assert!(engine.hasher().verify("x", "x").unwrap());
    let (subject, _) = engine.login("alice", "correct").unwrap();
    assert_eq!(subject.auth_id, 1);
    let result = engine.login("alice", "wrong");
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

#[test]
fn login_rotates_sessions_bound_to_a_previous_credential_version() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(1, "alice"), "alice", "pw")
        .unwrap()
        .expect("claim must succeed");
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .hasher(IdentityHasher)
        .build()
        .expect("engine construction must succeed");

    let (_, first) = engine.login("alice", "pw").unwrap();
    store.rotate_secret(&created.auth_id, "pw2").unwrap();

    let (_, second) = engine.login("alice", "pw2").unwrap();

    let first_storage = first.id().hash_for_storage();
    let second_storage = second.id().hash_for_storage();
    assert!(store.find_session(&first_storage).unwrap().is_none());
    assert!(store.find_session(&second_storage).unwrap().is_some());
}

#[test]
fn memory_store_clone_is_independent() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let session = Session::new(SessionId::generate().hash_for_storage(), 1, 100, 200);
    store.save_session(session.clone()).unwrap();

    let clone = store.clone();
    assert!(clone.find_credential("alice").unwrap().is_some());
    assert!(clone.find_session(session.id()).unwrap().is_some());

    clone.insert_user(TestUser::new(2, "bob"));
    clone.delete_session(session.id()).unwrap();

    assert!(store.resolve(&2).unwrap().is_none());
    assert!(clone.resolve(&2).unwrap().is_some());
    assert!(store.find_session(session.id()).unwrap().is_some());
    assert!(clone.find_session(session.id()).unwrap().is_none());
}

#[test]
fn builder_rejects_zero_ttl_and_zero_idle_timeouts() {
    let store = Arc::new(MemoryStore::<TestUser>::new());
    let zero_ttl = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store)).session_ttl_secs(0);
    assert!(zero_ttl.build().is_err());

    let zero_idle =
        AuthEngine::builder(Arc::clone(&store), Arc::clone(&store)).idle_timeout_secs(0);
    assert!(zero_idle.build().is_err());

    let valid = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .session_ttl_secs(60)
        .idle_timeout_secs(30);
    assert!(valid.build().is_ok());
}
