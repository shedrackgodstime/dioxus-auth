//! End-to-end tests for the auth-engine lifecycle (login → validate → logout).

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::{TestUser, hash_password};
use dioxus_auth::prelude::{
    AuthEngine, AuthError, InMemoryRateLimiter, MemoryStore, SessionId, SessionStore, UserStore,
};

fn seeded_engine() -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("s3cret"));
    let store = Arc::new(store);
    return AuthEngine::builder(Arc::clone(&store), store)
        .build()
        .expect("engine construction must succeed");
}

#[test]
fn login_then_validate_roundtrip() {
    let engine = seeded_engine();

    let (user, session) = engine.login("alice", "s3cret").unwrap();
    assert_eq!(user.id, 1);

    let validated = engine.validate_session(session.id()).unwrap().unwrap();
    assert_eq!(validated.id, 1);
}

#[test]
fn login_wrong_password_fails() {
    let engine = seeded_engine();

    let result = engine.login("alice", "wrong");
    assert!(result.is_err());
}

#[test]
fn login_unknown_user_fails() {
    let engine = seeded_engine();

    let result = engine.login("ghost", "whatever");
    assert!(result.is_err());
}

#[test]
fn logout_invalidates_the_session() {
    let engine = seeded_engine();

    let (_, session) = engine.login("alice", "s3cret").unwrap();
    engine.logout(session.id()).unwrap();

    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn logout_of_unknown_session_is_a_no_op() {
    let engine = seeded_engine();

    let result = engine.logout(&SessionId::generate());
    assert!(result.is_ok());
}

#[test]
fn revoke_known_session_reports_true() {
    let engine = seeded_engine();

    let (_, session) = engine.login("alice", "s3cret").unwrap();
    let revoked = engine.revoke_session(session.id()).unwrap();
    assert!(revoked);
    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn revoke_unknown_session_reports_false() {
    let engine = seeded_engine();

    let revoked = engine.revoke_session(&SessionId::generate()).unwrap();
    assert!(!revoked);
}

#[test]
fn validate_unknown_token_is_none() {
    let engine = seeded_engine();

    let validated = engine.validate_session(&SessionId::generate()).unwrap();
    assert!(validated.is_none());
}

#[test]
fn revoke_all_user_sessions_invalidates_every_active_session() {
    let engine = seeded_engine();

    let (_, first) = engine.login("alice", "s3cret").unwrap();
    let (_, second) = engine.login("alice", "s3cret").unwrap();
    assert!(engine.validate_session(first.id()).unwrap().is_some());
    assert!(engine.validate_session(second.id()).unwrap().is_some());

    engine.revoke_all_user_sessions(&1).unwrap();

    assert!(engine.validate_session(first.id()).unwrap().is_none());
    assert!(engine.validate_session(second.id()).unwrap().is_none());
}

#[test]
fn single_active_session_invalidates_the_previous_session() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .single_active_session(true)
        .build()
        .expect("engine construction must succeed");

    let (_, first) = engine.login("alice", "pw").unwrap();
    let (_, second) = engine.login("alice", "pw").unwrap();

    assert!(engine.validate_session(first.id()).unwrap().is_none());
    assert!(engine.validate_session(second.id()).unwrap().is_some());
}

#[test]
fn failed_attempts_are_rate_limited() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let limiter = InMemoryRateLimiter::new(2, std::time::Duration::from_secs(60));
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .rate_limiter(limiter)
        .build()
        .expect("engine construction must succeed");

    assert!(engine.login("alice", "wrong-1").is_err());
    assert!(engine.login("alice", "wrong-2").is_err());

    let result = engine.login("alice", "wrong-3");
    assert_eq!(result.unwrap_err(), AuthError::RateLimited);
}

#[test]
fn successful_validation_keeps_the_session_active() {
    let engine = seeded_engine();

    let (_, session) = engine.login("alice", "s3cret").unwrap();
    engine.validate_session(session.id()).unwrap();
    engine.validate_session(session.id()).unwrap();
    let validated = engine.validate_session(session.id()).unwrap().unwrap();

    assert_eq!(validated.id, 1);
}

#[test]
fn engine_getters_expose_configured_defaults() {
    let engine = seeded_engine();

    assert_eq!(engine.session_ttl_secs(), 7 * 24 * 60 * 60);
    assert_eq!(engine.idle_timeout_secs(), None);
    assert!(!engine.single_active_session());
    assert!(engine.user_store().find_by_id(&1).unwrap().is_some());
    assert!(
        engine
            .session_store()
            .find_session(&SessionId::new("0".repeat(64)))
            .unwrap()
            .is_none()
    );
    assert!(
        engine
            .hasher()
            .verify("s3cret", &hash_password("s3cret"))
            .unwrap()
    );
}

#[test]
fn builder_ttl_and_idle_timeout_flow_through_to_getters() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .session_ttl(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(10))
        .build()
        .expect("engine construction must succeed");

    assert_eq!(engine.session_ttl_secs(), 30);
    assert_eq!(engine.idle_timeout_secs(), Some(10));
}

#[test]
fn login_after_sign_out_revives_the_account() {
    let engine = seeded_engine();
    let (_, session) = engine.login("alice", "s3cret").unwrap();
    engine.logout(session.id()).unwrap();

    let (user, new_session) = engine.login("alice", "s3cret").unwrap();
    assert_eq!(user.id, 1);
    assert_ne!(session.id().as_str(), new_session.id().as_str());
    assert!(engine.validate_session(new_session.id()).unwrap().is_some());
}

#[test]
fn identifier_exists_returns_true_for_registered_account() {
    let engine = seeded_engine();
    let exists = engine.identifier_exists("alice").unwrap();

    assert!(exists);
}

#[test]
fn identifier_exists_returns_false_for_unknown_identifier() {
    let engine = seeded_engine();
    let exists = engine.identifier_exists("ghost").unwrap();

    assert!(!exists);
}

#[test]
fn sign_in_hook_is_fired_on_successful_login() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let fired = Arc::new(AtomicBool::new(false));
    let fired_flag = Arc::clone(&fired);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .on_sign_in(move |user| {
            assert_eq!(user.id, 1);
            fired_flag.store(true, Ordering::SeqCst);
        })
        .build()
        .expect("engine construction must succeed");

    engine.login("alice", "pw").unwrap();

    assert!(fired.load(Ordering::SeqCst));
}

#[test]
fn sign_out_hook_is_fired_on_logout() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let fired = Arc::new(AtomicBool::new(false));
    let fired_flag = Arc::clone(&fired);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .on_sign_out(move |_user| {
            fired_flag.store(true, Ordering::SeqCst);
        })
        .build()
        .expect("engine construction must succeed");

    let (_, session) = engine.login("alice", "pw").unwrap();
    engine.logout(session.id()).unwrap();

    assert!(fired.load(Ordering::SeqCst));
}

#[test]
fn on_session_validated_hook_is_fired_per_validation() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let count = Arc::new(AtomicBool::new(false));
    let count_flag = Arc::clone(&count);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .on_session_validated(move |_user| {
            count_flag.store(true, Ordering::SeqCst);
        })
        .build()
        .expect("engine construction must succeed");

    let (_, session) = engine.login("alice", "pw").unwrap();
    engine.validate_session(session.id()).unwrap();

    assert!(count.load(Ordering::SeqCst));
    assert_eq!(
        engine.login("alice", "wrong").unwrap_err(),
        AuthError::InvalidCredentials
    );
}
