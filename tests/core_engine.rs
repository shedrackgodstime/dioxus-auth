//! End-to-end tests for the auth-engine lifecycle (login → validate → logout).

mod common;

use std::sync::Arc;

use common::{hash_password, TestUser};
use dioxus_auth::engine::AuthEngine;
use dioxus_auth::error::AuthError;
use dioxus_auth::rate_limit::InMemoryRateLimiter;
use dioxus_auth::status::SessionId;
use dioxus_auth::store::MemoryStore;

fn seeded_engine() -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(
        TestUser::new(1, "alice"),
        "alice",
        hash_password("s3cret"),
    );
    let store = Arc::new(store);
    AuthEngine::builder(Arc::clone(&store), store)
        .build()
        .expect("engine construction must succeed")
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